# gonacl
Simple command line tool to encrypt/decrypt strings with nacl-box

It only does three things:
 - Generate keypairs for curve25519.
 - Encrypt a given string read from stdin and output the result to stdout.
 - Decrypt a given string read from stdin and output the result to stdout.

It does NOT do any key management.

Strings are first padded to 500 bytes and then encrypted.
Output is always base58, wrapped at 48 characters.

