# YAOG
Yet Another Openssl GUI : Qt base openssl GUI to create CSR, certificates, keys (RSA / DSA / EC)

This project aims to allow creating certificates in a quick and easy way.
Features :
- Single executable with no dependencies (openssl lib are included) : on Windows only for now
- Create auto sign certificates, CSR with immediate PEM display to copy/paste
- Conversion from certificate to csr (TODO)
- Allow RSA, DSA and elliptic curve keys
- Encrypt/descrypt keys, check certificate key match
- Set X509v3 extensions
- Import/export to PKCS#12
- Should work on any platform supported by Qt

Binary includes openssl library : https://www.openssl.org

Licence : GPL V3

