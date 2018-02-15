Documentation
===============

This software is all about creating certs/csr and keys quickly. 

Be careful to save you certificates and keys, as the software won't warn you about unsaved changes !

The main window has all you need : 

* Subject : all elements that will be set in your certificate / CSR. Only the CN will be set in a new CSR
* Key : type / length of key to generate. Check "password protected" to encrypt your key
* "Generate button" : see below

![MAIN](../img/main.jpg)

Generate button
---------------

![Gen](imggenerate.png)

you can generate :

* CSR + key : this will generate a CSR with the CN entered in "subject" and the key type/length/encryption in "key" group.

* Autosign + key : this will generate a X509 certificate with all elements in "subject" group (if not empty), key and extensions. The certificate will use it's own private key to sign itself

* CSR (existing key) : this will generate a CSR with the CN entered and the key in entered in PEM format at the lower right.

Note : the "generate key" button will only generate a key.

Certificate buttons
-------------------

* Display : display in human readable format the current certificate.

* Save/load : Save/load on disk

* Test cert & key match : check the certificate/csr public key is related to the private key in the "Key" box.

Key buttons
-----------

* Display : display in human readable format the current key

* Save/load : Save/load on disk

* Test : test if the key os correct (doesn't work for DSA)

* Encrypt/Decrypt : the key and output result in PEM format. Cipher used is the one in the top "Key" group.

PKCS12
------

Save or load pkcs12 format.
You can add certificate (previously saved on disk) with the current cert/key in a single P12
On the load dialog box, you can load the main certificate/key ("Import cert & key") or the other certificates in the P12 container.
 