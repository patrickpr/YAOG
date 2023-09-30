# YAOG

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/05ad904b205c4b598d3378d30a286d7b)](https://www.codacy.com/manual/patrick_34/YAOG?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=patrickpr/YAOG&amp;utm_campaign=Badge_Grade)

Yet Another Openssl GUI : Qt base openssl GUI to create CSR, certificates, keys (RSA / DSA / EC), P12 etc...

Current version :  1.1.2 using openSSL 1.1.1g 

If you have a problem, open an [issue](https://github.com/patrickpr/YAOG/issues/new). If you have a question go to [discussion](https://github.com/patrickpr/YAOG/discussions)

This project aims to allow creating certificates / keys in a quick and easy way.

Features :
- Single executable with no dependencies (openssl & Qt lib are included)
- Create auto sign certificates or CSR with immediate PEM display to copy/paste
- Certificate signing
- Stack to handle multiple certificates
- Conversion from certificate (private key) to csr
- Allow RSA, DSA and elliptic curve keys
- Encrypt/decrypt keys, check certificate / key match
- Set X509v3 extensions
- Import/export to PKCS#12
- Should work on any platform supported by Qt

Platforms for release binaries : 
- Windows release
- Will compile on Linux someday
- I don't have any Mac for OSX release. 

Binary includes openssl library version 1.1.1g compiled for 64 bits Windows platform.

Source code for openssl can be found at : https://www.openssl.org/source/

Licence : GPL V3

Installation / doc : ![here](docs/01-installation.md)

Main (and only !) window : 

![MAIN](img/main.jpg)

## See also
* [List of cryptography GUI tools](https://gist.github.com/stokito/eea7ee50d51e1db30122e2e33a62723e)

