/*
Copyright (c) 2014-2015 The scrambler-plugin authors. All rights reserved.

On 30.4.2015 - or earlier on notice - the scrambler-plugin authors will make
this source code available under the terms of the GNU Affero General Public
License version 3.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <dovecot/lib.h>
#include <dovecot/base64.h>
#include <dovecot/buffer.h>
#include <dovecot/str.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <errno.h>
#include <string.h>
#include <sodium.h>

#include "scrambler-common.h"

// Constants

const char scrambler_header[] = { 0xee, 0xff, 0xcc };

// Functions

void scrambler_initialize(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    if (sodium_init() == -1) {
        i_error("scrambler plugin failed to initialize libsodium");
    }
    i_info("scrambler plugin initialized");
}

const char *scrambler_read_line_fd(pool_t pool, int fd) {
    string_t *buffer = str_new(pool, MAXIMAL_PASSWORD_LENGTH);
    char *result = str_c_modifiable(buffer);
    char *pointer = result;

    ssize_t read_result = read(fd, pointer, 1);
    unsigned int bytes_read = 0;
    while (read_result != -1 && pointer[0] != '\n') {
        pointer++;
        bytes_read++;

        if (bytes_read > MAXIMAL_PASSWORD_LENGTH) {
            i_error("error reading form fd %d: password too long", fd);
            break;
        }

        read_result = read(fd, pointer, 1);
    }

    pointer[0] = 0;

    if (read_result == -1)
        i_error("error reading from fd %d: %s (%d)", fd, strerror(errno), errno);

    return result;
}

// base64encode with OpenSSL, from http://stackoverflow.com/a/16511093
static char *base64encode (const void * const buffer, const int size){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    BUF_MEM *mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.

    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                           //Initialize our memory sink BIO.
    BIO_push(b64_bio, mem_bio);            //Link the BIOs by creating a filter-sink BIO chain.

    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
    BIO_write(b64_bio, buffer, size);                            //Records base64 encoded data.
    BIO_flush(b64_bio);   //Flush data.  Necessary for b64 encoding, because of pad characters.

    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  //Store address of mem_bio's memory structure.
    BIO_set_close(mem_bio, BIO_NOCLOSE);   //Permit access to mem_ptr after BIOs are destroyed.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   //Makes space for end null.
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  //Adds null-terminator to tail.

    return (*mem_bio_mem_ptr).data; //Returns base-64 encoded data. (See: "buf_mem_st" struct).
}

// base64decode with OpenSSL, from http://stackoverflow.com/a/16511093
static size_t base64decode (const void * const in, const uint8_t ** const out) {
    const size_t inSize = strlen(in);

    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    char *base64_decoded = calloc((inSize*3)/4+1, sizeof(char));                   //+1 = null.

    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.

    BIO_write(mem_bio, in, inSize);                              //Base64 data saved in source.
    BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.

    int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.

    while (0 < BIO_read(b64_bio, base64_decoded+decoded_byte_index, 1) ){ //Read byte-by-byte.
        decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
    } //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.

    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).

    *out = (const uint8_t *) base64_decoded;

    return decoded_byte_index;
}

const char *scrambler_hash_password(
    const char * const password,
    const char * const salt,
    const uint64_t N,
    const uint64_t r,
    const uint64_t p,
    const uint32_t keylen
) {
    /* initial check, r,p must be non zero, N >= 2 and a power of 2 */
    if (__builtin_popcount(N) != 1 || N < 2) {
        i_error("scrambler_hash_password: N must be a power of two and bigger than one, current value is %lu", N);
        return NULL;
    }

    if (r == 0) {
        i_error("scrambler_hash_password: r must not be zero, current value is %lu", r);
        return NULL;
    }

    if (p == 0) {
        i_error("scrambler_hash_password: p must not be zero, current value is %lu", p);
        return NULL;
    }

    uint8_t rawKey[keylen];
    const uint8_t *bSalt;
    const size_t bSaltLen = base64decode(salt, &bSalt);

    const int errval = crypto_pwhash_scryptsalsa208sha256_ll(
                            (const uint8_t *) password, strlen(password),
                            bSalt, bSaltLen,
                            N, r, p,
                            rawKey, keylen);

    free((void *) bSalt);

    if (errval == 0) {
        return base64encode(rawKey, keylen);
    } else {
        return NULL;
    }
}

const EVP_CIPHER *scrambler_cipher(enum packages package) {
    switch (package) {
    case PACKAGE_RSA_2048_AES_128_CTR_HMAC:
        return EVP_aes_128_ctr();
    }
    return NULL;
}

void scrambler_generate_mac(
    unsigned char *tag, unsigned int *tag_size,
    const unsigned char *sources[], size_t source_sizes[],
    const unsigned char *key, size_t key_size
) {
    HMAC_CTX context;
    HMAC_CTX_init(&context);
    HMAC_Init_ex(&context, key, key_size, EVP_sha256(), NULL);

    unsigned int index = 0;
    const unsigned char *source = sources[index];
    size_t source_size = source_sizes[index];
    while (source != NULL) {
        HMAC_Update(&context, source, source_size);

        index++;
        source = sources[index];
        source_size = source_sizes[index];
    }

    HMAC_Final(&context, tag, tag_size);

    HMAC_CTX_cleanup(&context);
}

void scrambler_unescape_pem(char *pem) {
    while (*pem != '\0') {

        if (*pem == '_')
            *pem = '\n';

        pem++;
    }
}

EVP_PKEY *scrambler_pem_read_public_key(const char *source) {
    BIO *public_key_pem_bio = BIO_new_mem_buf((char *)source, -1);
    EVP_PKEY *result = PEM_read_bio_PUBKEY(public_key_pem_bio, NULL, NULL, NULL);
    BIO_free_all(public_key_pem_bio);

    if (result == NULL)
        i_error_openssl("scrambler_pem_read_public_key");
    return result;
}

EVP_PKEY *scrambler_pem_read_encrypted_private_key(const char *source, const char *password) {
    BIO *private_key_pem_bio = BIO_new_mem_buf((char *)source, -1);
    EVP_PKEY *result = PEM_read_bio_PrivateKey(private_key_pem_bio, NULL, NULL, (void *)password);
    BIO_free_all(private_key_pem_bio);

    if (result == NULL)
        i_error_openssl("scrambler_pem_read_encrypted_private_key");
    return result;
}

void i_error_openssl(const char *function_name) {
    char *output;
    BIO *output_bio = BIO_new(BIO_s_mem());
    ERR_print_errors(output_bio);
    BIO_get_mem_data(output_bio, &output);

    i_error("%s: %s", function_name, output);

    BIO_free_all(output_bio);
}

void i_debug_hex(const char *prefix, const unsigned char *data, size_t size) {
    T_BEGIN {
        string_t *output = t_str_new(1024);
        str_append(output, prefix);
        str_append(output, ": ");
        for (size_t index = 0; index < size; index++) {
            if (index > 0)
                str_append(output, " ");

            str_printfa(output, "%02x", data[index]);
        }
        i_debug("%s", str_c(output));
    } T_END;
}
