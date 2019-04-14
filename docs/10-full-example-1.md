Full example
===============

About
-----

In this example is describe how to generate a self signed CA, generate and sign a web server certificate, save all to a pkcs12 structure and renew the certificate.


Generate the CA
---------------

We need a certificate authority, self signed, with x509 extensions of a CA.

First, choose a rsa key of 2048 bits with a password protection : 

![KEY](img/1-fullex.jpg)

Next, set 

1) the name of the CA. Only the CN is mandatory
2) the digest used to sign the key
3) validity in days : here set to 10 years. 

![subject](img/7-fullex.jpg)

Date selection : You can either set validity in days starting from now, or select a starting and ending date by clicking ![date](img/3-fullex.jpg) and choosing start/end date
To revert to number of days, click :  ![date](img/5-fullex.jpg)

Next, add some X509 v3 extensions to make it look like a real CA, for example add "CA=true" as critical extension as this is needed to be seen as a CA.

Note : a critical extension means that if the browser - or other soft -, doesn't understand the extension, it should not accept the certificate.

Add an extension : 

![ext](img/9-fullex.jpg)

Then : 

1) Select "basicConstraint" as extension type
2) Click "Select"
3) Select "CA:TRUE"
4) Select Critical extension
5) Click "Add"
6) Click "OK" to add extension

![ext](img/11-fullex.jpg)

Note : 

* "Add and continue" will allow you to add the extension then reset the form for the next one
* "Reset form" will allow you to select a new extension
* You can edit the value if needed

You should now see the extension you added :

![ext](img/12-fullex.jpg)

Finaly select "Autosign+key" and click "generate".

Enter a serial number (or leave the random one) and click OK : ![serial](img/20-fullex.jpg)

The certificate and key (if no error is reported) are displayed - in pem format - in the lower edit box for you to cut & paste if needed. :

![serial](img/22-fullex.jpg)

Now the CA is generated, save the certificate for later use : click "save" in the Certificate box.

Next, push the certificate in the stack to select it as signing certificate : 

1) Click "Push cert" (the system will ask you for the key password to decrypt it)
2) Select it in the stack
3) Click "Sel for signing"
4) The "MY CA" certificate is now the signing certificate

![serial](img/24-fullex.jpg)

Generate a certificate to sign
------------------------------

Now, generate a certificate signing request (CSR) and sign it with the created CA.

Change the Name to : www.mysite.com, and change town name, change key to elliptic curve and disable password protection for key :

![csr](img/30-fullex.jpg)

Select "CSR+key" an click Generate.

Note : when generating aa csr only the Name, country, etc... are set into the CSR.

Push the csr into the stack for later use with "push cert".

Before signing, you must set : 

* Validity : set to 365 days for example
* X509 extensions : here set alternate names (delete CA=TRUE previous extension) :

![csr](img/32-fullex.jpg)

Then click "Sign" and 
* enter password of the CA key
* enter a serial number

the csr is replaced by a certificate.

Have a look at the certificate ("Display") to check all is OK : 

![csr](img/34-fullex.jpg)

Now save the certificate + key and the CA in a single PKC12 file : click "save PKCS12"

1) Enter a friendly name (optional)
2) Enter a password to protect the file
3) Click "Select from stack", select the CA certificate in the stack and click "Sel for P12"
4) The "MY CA" certificate (BUT NOT THE KEY) will be saved in the P12
5) Save to a file

![csr](img/36-fullex.jpg)

Renew a certificate
-------------------- 

To renew a certificate : 
1) Load the CA (cert + key or only the key)in the stack and select it as signing certificate
2) Load the certificate to renew in main window
3) Set Name, Country, etc...
4) Select "CSR (existing key)" and click Generate

Then setup validity, X509 extensions and sign it again as before. 

![csr](img/40-fullex.jpg)