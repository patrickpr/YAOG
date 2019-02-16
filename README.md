# YAOG
Yet Another Openssl GUI : Qt base openssl GUI to create CSR, certificates, keys (RSA / DSA / EC), P12 etc...

This project aims to allow creating certificates / keys in a quick and easy way.

Features :
- Single executable with no dependencies (openssl & Qt lib are included)
- Create auto sign certificates or CSR with immediate PEM display to copy/paste
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

Binary includes 
- openssl library : https://www.openssl.org 
- compiled by me for version 1.1.1 (crypto operations)
- and https://indy.fulgan.com/SSL/ for Qt SSL needing 1.0.2 (used for updates check). 

Licence : GPL V3

Installation / doc ![here](docs/01-installation.md)

Main (and only !) window : 

![MAIN](img/main.jpg)

