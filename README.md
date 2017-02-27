Dovecot encryption plugin
=========================

Requirements
------------

* Ensure GCC and the header files for libcrypto (OpenSSL) and libsodium are installed.

Installation
------------

* Use `make dovecot-install` to download and build dovecot 2.2.21 in a sub-directory. It's a local
  installation and your system wont be affected.

* Type `make all` to compile the plugin.

* Find the plugin at dovecot/target/lib/dovecot/lib18_scrambler_plugin.so.

Configuration
-------------

In order to run, the plugin needs the following configuration values (via the dovecot environment).

* `scrambler_plain_password` The plain user password. It's used to derive the hashed password to decrypt the
  private key.

* `scrambler_enabled` Can be `1` or `0`.

* `scrambler_public_key` The public key of the user. Formatted as _pem_.

* `scrambler_private_key` The encrypted private key of the user. Formatted as _pem_.

* `scrambler_private_key_salt` The salt of the hashed password that has been used to encrypt the private key.

* `userdb_scrambler_N` The scrypt parameter N used to derive the hashed password that has been used to encrypt  
  the private key.

* `userdb_scrambler_r` The scrypt parameter r used to derive the hashed password that has been used to encrypt  
  the private key.

* `userdb_scrambler_p` The scrypt parameter p used to derive the hashed password that has been used to encrypt  
  the private key.

* `userdb_scrambler_keylen` The length of the hashed password that has been used to encrypt the private key.

Example
-------
TODO config/passwd-generator
```
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:8192 -aes128 -pass stdin -out markus@mjott.pem
openssl rsa -outform pem -pubout -in markus@mjott.pem 
openssl rsa -outform pem -aes128 -passout stdin -in markus@mjott.pem
CREATE TABLE `users` (
	`id`	INTEGER NOT NULL,
	`username`	VARCHAR(255) NOT NULL,
	`domain`	VARCHAR(255) NOT NULL,
	`password`	TEXT,
	PRIMARY KEY(id)
);
CREATE TABLE "keys" (
	`userid`	INTEGER,
	`enabled`	INTEGER NOT NULL,
	`scrypt_N`	NUMERIC NOT NULL,
	`scrypt_r`	INTEGER NOT NULL,
	`scrypt_p`	INTEGER NOT NULL,
	`scrypt_keylen`	INTEGER NOT NULL,
	`scrypt_salt`	TEXT NOT NULL,
	`public_key`	TEXT NOT NULL,
	`private_key`	TEXT NOT NULL,
	FOREIGN KEY(`userid`) REFERENCES users ( id )
)
```
Migration
---------

The migration of unencrypted mailboxes has to be done by a separate tool and is _not_ part of this project.

Project
-------

Concept, design and realization by [Posteo e.K.](https://posteo.de).
The implementation was provided by [simia.tech GbR](http://simiatech.com).
An security audit has been provided by [Cure53](https://cure53.de).
