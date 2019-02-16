#include "sslcertificates.h"
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  #include <openssl\applink.c>
#else
  #include <openssl\applink.c>
#endif

#include <string.h>

#include <openssl/ossl_typ.h>

#ifdef Q_OS_WIN
#include <windows.h> // for Sleep
#endif

void(*SSLCertificates::output_display)(char*)=nullptr;
int SSLCertificates::abortnow=0;

SSLCertificates::SSLCertificates()
{
    this->keyLength=1024;
    this->x509=nullptr;
    this->pkey=nullptr;

    if ((this->pkey=EVP_PKEY_new()) == nullptr)    throw 10;
    if ((this->x509=X509_new())     == nullptr)    throw 20;
    if ((this->rsakey=RSA_new())    == nullptr)    throw 10;
    if ((this->csr=X509_REQ_new())  == nullptr)    throw 10;
    if ((this->eckey=EC_KEY_new())  == nullptr)    throw 10;
    if ((this->dsakey=DSA_new())    == nullptr)    throw 10;

    this->output_display=nullptr;
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    this->bio_err=BIO_new_fp(stdout, BIO_NOCLOSE);

    // OpenSSL load of quite everything.
    ERR_load_crypto_strings (); // Load error strings
    SSL_load_error_strings(); // Load errors (as ssl app)
    OpenSSL_add_all_algorithms(); // Add all encryption algo
    OpenSSL_add_all_digests(); // Add all digests
    OpenSSL_add_all_ciphers(); // all ciphers
    
    SSL_library_init();

    SSLCertificates::abortnow=0;
    this->SSLErrorNum=-1;
    this->SSLError=0;
    this->set_digest((char*)"sha256");
    this->subjectNum=0;
    this->keyType=0;
    this->set_cipher((char*)"aes256");
    this->startDate=this->endDate=nullptr;
    this->serialnum=1;
    this->extensionNum=0;
    this->p12Name=nullptr;
    this->ca=nullptr;
    this->caListCerts.clear();
    this->caListCN.clear();

    //TODO : random init
}

SSLCertificates::~SSLCertificates()
{
    if (this->x509 != nullptr) X509_free(this->x509);
    if (this->pkey != nullptr) EVP_PKEY_free(this->pkey);
    if (this->csr  != nullptr) X509_REQ_free(this->csr);
    // TODO : (Memory leak)
    // EVP_PKEY_free also free the RSA or EC or DSA : must check which one is used before free
    //if (this->rsakey != nullptr) RSA_free(this->rsakey);
    //if (this->eckey != nullptr) EC_KEY_free(this->eckey);
    if (this->startDate != nullptr) ASN1_TIME_free(this->startDate);
    if (this->endDate != nullptr) ASN1_TIME_free(this->endDate);
    for (int i=0; i<this->subjectNum;i++)
    {
        if (this->subject_id[i]!=nullptr) free(this->subject_id[i]);
        if (this->subject[i]!=nullptr) free(this->subject[i]);
    }
    //TODO clear also extensions

#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    CRYPTO_cleanup_all_ex_data();

    // TODO : this writes mem leaks with 1.0.2, not found in 1.1 -> check new
    //CRYPTO_mem_leaks(this->bio_err);
    BIO_free(this->bio_err);
    if (p12Name != nullptr) free(p12Name);
    if (ca!=nullptr) sk_X509_free(ca);
    caListCN.clear();
    for (std::vector<X509*>::iterator x509 = caListCerts.begin();
         x509 != caListCerts.end(); ++x509)
    {
      X509_free(*x509);
    }
    caListCerts.clear();

    RAND_cleanup();
}

/*************************** Display and errors functions ************************/

void SSLCertificates::print_ssl_errors(char* buffer,size_t size)
{
    char linebuf[200]="";
    if (this->SSLErrorNum == -1)
    {
        strcpy(buffer,"No current SSL errors ");
        return;
    }
    buffer[0]='\0';
    for (int i=0;i<=this->SSLErrorNum;i++)
    {
       sprintf(linebuf,"Lib : %s, doing : %s, reason : %s (%i/%i/%i)\n",
               ERR_lib_error_string(this->SSLErrorList[i]),
               ERR_func_error_string((this->SSLErrorList[i])),
               ERR_reason_error_string((this->SSLErrorList[i])),
               ERR_GET_LIB(this->SSLErrorList[i]),
               ERR_GET_FUNC(this->SSLErrorList[i]),
               ERR_GET_REASON(this->SSLErrorList[i]));
       if ((strlen (buffer)+strlen (linebuf)) > size)
       {
           strcat(buffer,"[...]");
           this->SSLErrorNum=-1;
           return;
       }
       strcat(buffer,linebuf);
    }
    this->SSLErrorNum=-1;
}

void SSLCertificates::get_ssl_errors()
{
    unsigned long int errcode;

    while ((errcode= ERR_get_error())!= 0) {
        this->SSLError=1;
        this->SSLErrorList[++this->SSLErrorNum]=errcode;
        if (this->SSLErrorNum >= MAX_SSL_ERRORS) this->SSLErrorNum=0; //cycle on overflow
    }
}

void SSLCertificates::empty_ssl_errors()
{
    this->SSLErrorNum=-1;
    this->SSLError=0;
}

void SSLCertificates::set_display_callback(void (*callback)(char *))
{
    SSLCertificates::output_display=callback;
}

void SSLCertificates::clear_display_callback()
{
   SSLCertificates::output_display=nullptr;
}

/*************************** Certificate functions ************************/

int SSLCertificates::add_cert_object_byname(const char* label,const unsigned char* content)
{
   // Just to check it is valid
    /*
    X509_NAME2* X509_name= X509_get_subject_name(this->x509);
   if (X509_NAME_add_entry_by_txt(X509_name,label,
                                  MBSTRING_ASC,
                                  content,
                                  -1,   // auto length
                                  -1,   // loc
                                  0     // set
                                  ) == 0)
   {
       this->get_ssl_errors();
       return 1;
   }
*/
   this->subject_id[this->subjectNum] = strdup(label);
   this->subject[this->subjectNum] = (unsigned char*) strdup((const char*)content);
   this->subjectNum++;

   return 0;
}

int SSLCertificates::set_object(const unsigned char* oCN, const unsigned char* oC, const unsigned char* oS,
               const unsigned char* oL, const unsigned char* oO, const unsigned char* oOU,
               const unsigned char *omail)
{
    if (strcmp((const char*)oCN,"")!=0)
    {
        if (strcmp((const char*)omail,"")!=0)
        {
            std::string newCN=(const char*)oCN;
            newCN += "/emailAddress=";
            newCN += (const char*)omail;
            if (this->add_cert_object_byname("CN",(const unsigned char*)newCN.data()) != 0) return 1;
        }
        else
            if (this->add_cert_object_byname("CN",oCN) != 0) return 1;
    }
    else
        return 1;
    if (strcmp((const char*)oOU,"")!=0)
        if (this->add_cert_object_byname("OU",oOU) != 0) return 1;
    if (strcmp((const char*)oO,"")!=0)
        if (this->add_cert_object_byname("O",oO) != 0) return 1;
    if (strcmp((const char*)oL,"")!=0)
        if (this->add_cert_object_byname("L",oL) != 0) return 1;
    if (strcmp((const char*)oS,"")!=0)
        if (this->add_cert_object_byname("ST",oS) != 0) return 1;
    if (strcmp((const char*)oC,"")!=0)
        if (this->add_cert_object_byname("C",oC) != 0) return 1;


    return 0;
}

int SSLCertificates::set_key_params(unsigned int keyparam, int keytype, char* ec )
{
    int i;
    switch (keytype)
    {
    case KeyRSA:
        this->keyLength=keyparam;
        this->keyType=keytype;
        break;
    case KeyEC:
        for (i=0;i< keyECListNum; i++)
        {
            if (!strcmp(ec,this->keyECList[i]))
            {
                this->keyECType=this->keyECListNIDCode[i];
                this->keyType=keytype;
                return 0;
            }
        }
        return 1;
    case KeyDSA:
        this->keyLength=keyparam;
        this->keyType=keytype;
        break;
    default:
        return 1;
    }
    return 0;
}

int SSLCertificates::set_digest(char *digest)
{
    EVP_MD* digestalg;
    if ((digestalg=(EVP_MD*)EVP_get_digestbyname(digest))==nullptr)
    {
        this->get_ssl_errors();
        return 1;
    }
    this->useDigest=digestalg;
    return 0;
}

int SSLCertificates::set_cipher(char *cipher)
{
    EVP_CIPHER* cipheralg;
    if ((cipheralg=(EVP_CIPHER*)EVP_get_cipherbyname(cipher))==nullptr)
    {
        this->get_ssl_errors();
        return 1;
    }
    this->useCipher=cipheralg;
    return 0;
}

int SSLCertificates::set_X509_validity(char *start,char *end)
{
    this->startDate=ASN1_TIME_new();
    this->endDate=ASN1_TIME_new();

    if (ASN1_TIME_set_string(this->startDate, start)!=1)
    {
        return 1;
    }
    if (ASN1_TIME_set_string(this->endDate, end)!=1)
    {
        return 1;
    }
    return 0;
    /* BUG also with this....
    if (ASN1_TIME_set(this->startDate, start) == nullptr)
       return 1;
    if ((this->endDate = ASN1_TIME_set(NULL, end)) == NULL)
    {
        ASN1_TIME_free(this->startDate);
        return 1;
    }*/
//  TODO : BUG This (ASN1_TIME_diff) makes program crash on debug mode with QT......
//  (SIGSEV at startup : while this is not even called...)
/*
    int day, sec;
    if (!ASN1_TIME_diff(&day, &sec, this->startDate, this->endDate))
    {
        ASN1_TIME_free(this->startDate);
        ASN1_TIME_free(this->endDate);
        return 255; // Why would this happen ?
    }

    if (day < 0 || sec < 0)
    {
       ASN1_TIME_free(this->startDate);
        ASN1_TIME_free(this->endDate);
        return 2;
    }*/
    return 0;

}

void SSLCertificates::set_X509_serial(unsigned int serial)
{
    this->serialnum=serial;
}

int SSLCertificates::create_key()
{

    if (this->output_display != nullptr) this->output_display((char*)"Starting key generation\n");

    BIGNUM *f4 = BN_new(); // Init exponent (65537)
    BN_set_word(f4, RSA_F4);
    // Callback structure
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    BN_GENCB* cb = BN_GENCB_new();
#else
    BN_GENCB cbn;
    BN_GENCB* cb=&cbn;
#endif
    BN_GENCB_set(cb,this->callback, nullptr);

    int retcode;

    switch (this->keyType)
    {
    case KeyRSA:
        retcode = RSA_generate_key_ex(this->rsakey, this->keyLength, f4,cb);

        BN_free(f4);
        if (retcode != 1)
        {
            this->get_ssl_errors();
            return 3;
        }
        if (!EVP_PKEY_assign_RSA(this->pkey,this->rsakey))
            {
            this->get_ssl_errors();
            return 1;
            }
        break;
    case KeyEC:
        if((this->eckey = EC_KEY_new_by_curve_name(this->keyECType))==nullptr)
        {
            this->get_ssl_errors();
            return 1;
        }
        if (EC_KEY_generate_key(this->eckey)!=1)
        {
            this->get_ssl_errors();
            return 1;
        }
        if (EVP_PKEY_assign_EC_KEY(this->pkey,this->eckey) != 1)
        {
            this->get_ssl_errors();
            return 1;
        }
        break;
    case KeyDSA:
        retcode = DSA_generate_parameters_ex(this->dsakey, this->keyLength,
                        nullptr,0, // TODO Seed null -> random
                        nullptr, nullptr,// counter unused TODO : check if usefull
                        cb);
        if (retcode == 0)
        {
            this->get_ssl_errors();
            return 1;
        }
        retcode = DSA_generate_key(this->dsakey);
        if (retcode == 0)
        {
            this->get_ssl_errors();
            return 1;
        }
        if (EVP_PKEY_assign_DSA(this->pkey,this->dsakey) != 1)
        {
            this->get_ssl_errors();
            return 1;
        }
        break;
    default:
        if (this->output_display != nullptr) this->output_display((char*)"Unknown key type\n");
        return 1;
    }

    if (this->output_display != nullptr) this->output_display((char*)"Key generation finished\n");
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    BN_GENCB_free(cb); // TODO : also free in other cases -> change function structure
#endif
    return 0;
}

int SSLCertificates::create_cert()
{
    X509_NAME2 *x509Name;
    std::string value;
    int i;

    if (this->output_display != nullptr) this->output_display((char*)"Starting certificate generation\n");
    if (X509_set_version(this->x509,2) == 0)
    {
        this->get_ssl_errors();
        return 1;
    }
    if (ASN1_INTEGER_set(X509_get_serialNumber(this->x509),this->serialnum) == 0)
    {
        this->get_ssl_errors();
        return 1;
    }

    if ((this->startDate == nullptr) || (this->endDate == nullptr))
    {
        return 2;
    }
    if ((X509_set_notBefore(this->x509,this->startDate)!=1)
            || (X509_set_notAfter(this->x509,this->endDate)!=1))
    {
            this->get_ssl_errors();
            return 1;
    }

    if (X509_set_pubkey(this->x509,this->pkey) == 0)
    {
        this->get_ssl_errors();
        return 1;
    }

    x509Name=X509_get_subject_name(this->x509);

    for (int i=0; i<this->subjectNum;i++)
    {
        if (X509_NAME_add_entry_by_txt(x509Name,this->subject_id[i],
                                   MBSTRING_ASC, this->subject[i], -1,
                                   -1, 0) == 0)
        {
            this->get_ssl_errors();
            return 1;
        }
    }
    X509_set_issuer_name(this->x509,x509Name);
    /* Add various extensions: standard extensions */
    for (i=0;i<this->extensionNum;i++)
    {
        if (this->extensionCritical[i]==0)
            value="";
        else
            value="critical,";

        value += this->extensionVal[i].data();
        if (this->add_ext_bytxt(this->x509,(char*)this->extensionName[i].data(),(char*)value.data()) == 0)
        {
            this->get_ssl_errors();
            return 1;
        }
    }
    //this->add_ext(this->x509, NID_basic_constraints, (char*)"critical,CA:TRUE");

    if (!X509_sign(this->x509,this->pkey,this->useDigest))
    {
        this->get_ssl_errors();
        return 1;
    }
    if (this->output_display != nullptr) this->output_display((char*)"finished certificate generation\n");
    return 0;
}

int SSLCertificates::create_csr()
{
    X509_NAME2   *x509Name = nullptr;
    int i;
    std::string value;
    //if (RAND_load_file(_RAND_FILENAME, _RAND_LOADSIZE) != _RAND_LOADSIZE) {

    if (!X509_REQ_set_version(this->csr, 0L))        /* Version 1 */
    {
        this->get_ssl_errors();
        return 1;
    }

    if (!X509_REQ_set_pubkey(this->csr, this->pkey))
    {
        this->get_ssl_errors();
        return 1;
    }

    if (!(x509Name  = X509_REQ_get_subject_name(this->csr)))
    {
        this->get_ssl_errors();
        return 1;
    }

    for (int i=0; i<this->subjectNum;i++)
    {
        if (X509_NAME_add_entry_by_txt(x509Name,this->subject_id[i],
                                   MBSTRING_ASC, this->subject[i], -1,
                                   -1, 0) == 0)
        {
            this->get_ssl_errors();
            return 1;
        }
    }

    /* Add various extensions: standard extensions */
    //TODO : not valid for CSR, change this
    for (i=0;i<this->extensionNum;i++)
    {
        if (this->extensionCritical[i]==0)
            value="";
        else
            value="critical,";

        value += this->extensionVal[i].data();
        if (this->add_ext_bytxt(this->x509,(char*)this->extensionName[i].data(),(char*)value.data()) == 0)
        {
            this->get_ssl_errors();
            return 1;
        }
    }
    if (!X509_REQ_sign(this->csr, this->pkey, this->useDigest)) {
        this->get_ssl_errors();
        return 1;
    }
    return 0;
}

int SSLCertificates::get_csr_PEM(char *Skey, size_t maxlength) {

    BIO *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;
    if (!PEM_write_bio_X509_REQ(mem,this->csr))
    {
        this->get_ssl_errors();
        BIO_free(mem);
        return 3;
    }
    BIO_get_mem_ptr(mem, &bptr);
    if (bptr->length == 0) {
        BIO_free(mem);return 1;
    }
    if (bptr->length >= maxlength) {
        BIO_free(mem);return 2;
    }
    strncpy(Skey,bptr->data,bptr->length+1);
    Skey[bptr->length+1]='\0';
    BIO_free(mem);
    return 0;
}

int SSLCertificates::get_csr_HUM(char* Skey,size_t maxlength) {

    BIO *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;


    if (X509_REQ_print(mem,this->csr)==0) {
        this->get_ssl_errors();
        strncpy(Skey,"Error printing certificate",maxlength);
        return 3;
    }
    BIO_get_mem_ptr(mem, &bptr);
    if (bptr->length == 0) {
        BIO_free(mem);return 1;
    }
    if (bptr->length >= maxlength) {
        BIO_free(mem);return 2;
    }
    strncpy(Skey,bptr->data,bptr->length+1);
    Skey[bptr->length+1]='\0';
    BIO_free(mem);
    return 0;
}

int SSLCertificates::set_csr_PEM(const char* Skey, char* password)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_puts(mem,Skey);

    this->csr = PEM_read_bio_X509_REQ(mem,nullptr,
                    &SSLCertificates::pem_password_callback,password);
        //(BIO *bp, EVP_PKEY **x,pem_password_cb *cb, void *u);
    BIO_free(mem);
    if (this->csr == nullptr)
    {
        this->get_ssl_errors();
        if ((ERR_GET_REASON(this->SSLErrorList[this->SSLErrorNum])==OPENSSL_BAD_PASSWORD_ERR)
                || (ERR_GET_REASON(this->SSLErrorList[this->SSLErrorNum])==OPENSSL_BAD_DECRYPT_ERR))
        {
            this->empty_ssl_errors();
            return 2;
        }
        return 1;
    }
    return 0;
}

int SSLCertificates::get_cert_PEM(char *Skey, size_t maxlength, X509 *locX509) {

    BIO *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;
    // take local if not specified
    if (locX509==nullptr) locX509=this->x509;

    if (!PEM_write_bio_X509(mem,locX509))
    {
        this->get_ssl_errors();
        BIO_free(mem);
        return 3;
    }
    BIO_get_mem_ptr(mem, &bptr);
    if (bptr->length == 0) {
        BIO_free(mem);return 1;
    }
    if (bptr->length >= maxlength) {
        BIO_free(mem);return 2;
    }
    strncpy(Skey,bptr->data,bptr->length+1);
    Skey[bptr->length+1]='\0';
    BIO_free(mem);
    return 0;
}

int SSLCertificates::get_cert_HUM(char* Skey,size_t maxlength) {

    BIO *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;


    if (X509_print(mem,this->x509)==0) {
        this->get_ssl_errors();
        strncpy(Skey,"Error printing certificate",maxlength);
        return 3;
    }
    BIO_get_mem_ptr(mem, &bptr);
    if (bptr->length == 0) {
        BIO_free(mem);return 1;
    }
    if (bptr->length >= maxlength) {
        BIO_free(mem);return 2;
    }
    strncpy(Skey,bptr->data,bptr->length+1);
    Skey[bptr->length+1]='\0';
    BIO_free(mem);
    return 0;
}

int SSLCertificates::get_cert_CN(char* CN,size_t maxlength, X509* cert)
{
  int common_name_loc = -1;
   X509_NAME_ENTRY *common_name_entry = nullptr;
   ASN1_STRING *common_name_asn1 = nullptr;
   char *common_name_str = nullptr;

   if (cert == nullptr)
   {
     cert=this->x509;
   }
   // Find the position of the CN field in the Subject field of the certificate
   common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(cert), NID_commonName, -1);
   if (common_name_loc < 0) {
           return 1;
   }

   // Extract the CN field
   common_name_entry = X509_NAME_get_entry(X509_get_subject_name(cert), common_name_loc);
   if (common_name_entry == nullptr) {
           return 1;
   }

   // Convert the CN field to a C string
   common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
   if (common_name_asn1 == nullptr) {
           return 1;
   }
#if OPENSSL_VERSION_NUMBER > 0x10100000L
   common_name_str = (char *) ASN1_STRING_get0_data(common_name_asn1);
#else
   common_name_str = (char *) ASN1_STRING_data(common_name_asn1);
#endif
   // Make sure there isn't an embedded NUL character in the CN
   if ((size_t)ASN1_STRING_length(common_name_asn1) != strlen(common_name_str)) {
           return 1;
   }
   if (strlen(common_name_str)>=maxlength)
     {
       return 2;
     }
   strncpy(CN,common_name_str,strlen(common_name_str));
   CN[strlen(common_name_str)]=0;
   return 0;
}

int SSLCertificates::set_cert_PEM(const char* Skey, const char* password)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_puts(mem,Skey);

    this->x509 = PEM_read_bio_X509(mem,nullptr,
                    &SSLCertificates::pem_password_callback,(void*)password);
        //(BIO *bp, EVP_PKEY **x,pem_password_cb *cb, void *u);
    BIO_free(mem);
    if (this->x509 == nullptr)
    {
        this->get_ssl_errors();
        if ((ERR_GET_REASON(this->SSLErrorList[this->SSLErrorNum])==OPENSSL_BAD_PASSWORD_ERR)
                || (ERR_GET_REASON(this->SSLErrorList[this->SSLErrorNum])==OPENSSL_BAD_DECRYPT_ERR))
        {
            this->empty_ssl_errors();
            return 2;
        }
        return 1;
    }
    return 0;
}

int SSLCertificates::get_key_PEM(char *Skey, size_t maxlength) {

    BIO *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;
    switch (this->keyType)
    {
    case KeyDSA:   // PEM_write_bio_DSAPrivateKey
    case KeyRSA:
    case KeyEC:
        if (!PEM_write_bio_PrivateKey(mem,this->pkey,nullptr,nullptr,0,nullptr, nullptr))
        {
            this->get_ssl_errors();
            BIO_free(mem);
            return 3;
        }
        break;
    default:
        BIO_free(mem);
        return 3;
    }

    BIO_get_mem_ptr(mem, &bptr);
    if (bptr->length == 0) {
        BIO_free(mem);return 1;
    }
    if (bptr->length >= maxlength) {
        BIO_free(mem);return 2;
    }
    strncpy(Skey,bptr->data,bptr->length);
    Skey[bptr->length]='\0';
    BIO_free(mem);
    return 0;
}

int SSLCertificates::get_key_HUM(char* Skey,size_t maxlength) {

    BIO *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;

    switch (this->keyType) {
    case KeyRSA:
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        if (RSA_print(mem,EVP_PKEY_get0_RSA(pkey),0)==0) {
#else
        if (RSA_print(mem,pkey->pkey.rsa,0)==0) {
#endif
          this->get_ssl_errors();
            strncpy(Skey,"Error printing RSA key",maxlength);
            return 3;
        }
        break;
    case KeyEC:
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        if (EC_KEY_print(mem,EVP_PKEY_get0_EC_KEY(pkey),0)==0)
#else
        if (EC_KEY_print(mem,pkey->pkey.ec,0)==0)
#endif
        {
            this->get_ssl_errors();
            strncpy(Skey,"Error printing EC key",maxlength);
            return 3;
        }
        break;
    case KeyDSA:
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        if (DSA_print(mem,EVP_PKEY_get0_DSA(pkey),0)==0)
#else
        if (DSA_print(mem,pkey->pkey.dsa,0)==0)
#endif
        {
            this->get_ssl_errors();
            strncpy(Skey,"Error printing DSA key",maxlength);
            return 3;
        }
        break;
    default:
        this->get_ssl_errors();
        strncpy(Skey,"Unknown key",maxlength);
        return 3;
    }


    BIO_get_mem_ptr(mem, &bptr);
    if (bptr->length == 0) {
        this->get_ssl_errors();
        BIO_free(mem);return 1;
    }
    if (bptr->length >= maxlength) {
        this->get_ssl_errors();
        BIO_free(mem);return 2;
    }
    strncpy(Skey,bptr->data,bptr->length);
    Skey[bptr->length]='\0';
    BIO_free(mem);
    return 0;
}

int SSLCertificates::set_key_PEM(const char* Skey, char* password=nullptr)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_puts(mem,Skey);

    this->pkey = PEM_read_bio_PrivateKey(mem,nullptr,
                    &SSLCertificates::pem_password_callback,password);
    //printf("keytype : %i\n",this->pkey->type);fflush (stdout);
    BIO_free(mem);
    if (this->pkey == nullptr)
    {
        int firstError=this->SSLErrorNum+1;
        this->get_ssl_errors();
        if ((ERR_GET_REASON(this->SSLErrorList[firstError])==OPENSSL_BAD_PASSWORD_ERR)
                || (ERR_GET_REASON(this->SSLErrorList[firstError])==OPENSSL_BAD_DECRYPT_ERR))
        {
            this->empty_ssl_errors();
            return 2;
        }
        printf("SSL error : %i\n",ERR_GET_REASON(this->SSLErrorList[this->SSLErrorNum]));fflush (stdout);
        return 1;
    }
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    switch (EVP_PKEY_type(EVP_PKEY_id(this->pkey)))
#else
    switch (get_key_type())
#endif
    {
    case EVP_PKEY_RSA:
        this->keyType=KeyRSA;
        break;
    case EVP_PKEY_EC:
        this->keyType=KeyEC;
        break;
    case EVP_PKEY_DSA:
        this->keyType=KeyDSA;
        break;
    default:
        return 3;
        break;
    }

    return 0;
}

int SSLCertificates::get_key_type(char* keytype)
{
    switch (this->keyType)
    {
    case KeyRSA:
    case KeyDSA:
    case KeyEC:
        strcpy(keytype,keyTypeList[this->keyType-1]);
        return 0;
    }
    strcpy(keytype,"Unkown");
    return 1;
}

int SSLCertificates::get_key_PEM_enc(char *Skey, size_t maxlength, char* password)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;

    switch (this->keyType)
    {
    case KeyDSA: // PEM_write_bio_DSAPrivateKey
    case KeyRSA:
    case KeyEC:
        if (PEM_write_bio_PKCS8PrivateKey(mem,this->pkey,this->useCipher,
                                         (char*) password,strlen(password),nullptr, nullptr) == 0)
        {
            this->get_ssl_errors();
            BIO_free(mem);
            return 3;
        }
        break;
    default:
        BIO_free(mem);
        return 3;
    }

    BIO_get_mem_ptr(mem, &bptr);
    if (bptr->length == 0) {
        this->get_ssl_errors();BIO_free(mem);return 1;
    }
    if (bptr->length >= maxlength) {
        BIO_free(mem);return 2;
    }
    strncpy(Skey,bptr->data,bptr->length+1);
    Skey[bptr->length+1]='\0';
    BIO_free(mem);
    return 0;
}

int SSLCertificates::save_to_pkcs12(FILE *file, char* name,char* pass)
{
    PKCS12 *newkey;
    newkey = PKCS12_create(
                pass, //char *pass
                name, // char *name
                this->pkey, //EVP_PKEY *pkey
                this->x509, //X509 *cert,
                this->ca,   //STACK_OF(X509) *ca,
                0,      //    int nid_key
                0,      //    int nid_cert
                PKCS12_DEFAULT_ITER,      //    int iter
                0,      //    int mac_iter
                NID_key_usage);      //   int keytype
    if (newkey==nullptr)
      {
        this->get_ssl_errors();
        return 1;
      }
    if (i2d_PKCS12_fp(file,newkey) <=0)
    {
        this->get_ssl_errors();
        return 2;
    }
    PKCS12_free(newkey);
    return 0;
}

char *SSLCertificates::find_friendly_name(PKCS12 *p12)
{
    STACK_OF(PKCS7) *safes = PKCS12_unpack_authsafes(p12);
    int n, m;
    char *name = nullptr;
    PKCS7 *safe;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    PKCS12_SAFEBAG *bag;

    if ((safes = PKCS12_unpack_authsafes(p12)) == nullptr)
        return nullptr;

    for (n = 0; n < sk_PKCS7_num(safes) && name == nullptr; n++) {
        safe = sk_PKCS7_value(safes, n);
        if (OBJ_obj2nid(safe->type) != NID_pkcs7_data
                || (bags = PKCS12_unpack_p7data(safe)) == nullptr)
            continue;

        for (m = 0; m < sk_PKCS12_SAFEBAG_num(bags) && name == nullptr; m++) {
            bag = sk_PKCS12_SAFEBAG_value(bags, m);
            name = PKCS12_get_friendlyname(bag);
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }

    sk_PKCS7_pop_free(safes, PKCS7_free);

    return name;
}

int SSLCertificates::get_pkcs12_certs()
{
  // not initialized or empty
  if ((ca==nullptr)||(sk_X509_num(ca)==0)) return 0;

  int num=sk_X509_num(ca);
  char p12CN[100];
  std::string p12CNStr;
  X509* p12Cert;

  caListCN.reserve(num);
  caListCerts.reserve(num);
  for (int i=0;i<num;i++)
  {
    p12Cert=X509_dup(sk_X509_value(ca,i));
    caListCerts.push_back(p12Cert);
    if (this->get_cert_CN(p12CN,100,p12Cert) == 0)
    {
      p12CNStr.assign(p12CN);      
    }
    else
    {
       p12CNStr.assign("<Unknown CN>");
    }
    caListCN.push_back(p12CNStr);
  }
  return num;
}

int SSLCertificates::get_pkcs12_certs_num()
{
  return this->caListCerts.size();
}

std::string SSLCertificates::get_pkcs12_certs_CN(unsigned int n)
{
  if (n>=this->caListCN.size()) return std::string("");
  return this->caListCN.at(n);
}

int SSLCertificates::get_pkcs12_certs_pem(unsigned int n,char *Skey, size_t maxlength)
{
  if (n>=this->caListCerts.size()) return 10;
  return get_cert_PEM(Skey,maxlength,this->caListCerts.at(n));
}

int SSLCertificates::load_pkcs12(FILE *file, const char* password)
{
  PKCS12 *p12;
  if ((p12=d2i_PKCS12_fp(file,nullptr)) == nullptr)
  {
    this->get_ssl_errors();
    return 1;
  }
  if (!PKCS12_parse(p12, password, &pkey, &x509, &ca)) {
      this->get_ssl_errors();
      return 2;
  }
  switch (EVP_PKEY_type(EVP_PKEY_id(this->pkey)))
  { // TODO : use get_key_type instead
    case EVP_PKEY_RSA: this->keyType = KeyRSA; break;
    case EVP_PKEY_DSA: this->keyType = KeyDSA; break;
    case EVP_PKEY_EC: this->keyType = KeyEC; break;
    default: PKCS12_free(p12);return 3;
  }
  char * name=find_friendly_name(p12);
  get_pkcs12_certs();
  p12Name=strdup(name);
  // TODO check mem leak. free(name) doest sigsev.
  //free(name);
  PKCS12_free(p12);
  return 0;
}

char *SSLCertificates::get_pkcs12_name()
{
  return this->p12Name;
}

int SSLCertificates::add_pkcs12_ca(const char* Skey)
{
  if (ca==nullptr)
  {
    ca = sk_X509_new_null();
  }
  SSLCertificates * loccert=new SSLCertificates();
  if (loccert->set_cert_PEM(Skey,"") != 0)
  {
    return 1;
  }
  sk_X509_push(ca,loccert->x509);
  return 0;
}

int SSLCertificates::callback(int p, int , BN_GENCB*)
{
    char c[2];
    c[0]='B';
    c[1]=0;

    if (p == 0) c[0]='.';
    if (p == 1) c[0]='+';
    if (p == 2) c[0]='*';
    if (p == 3) c[0]='\n';
    SSLCertificates::output_display(c);
    //printf("callback : %i \n",p);
    if (SSLCertificates::abortnow == 1) return 0;
    return 1;
}

int SSLCertificates::pem_password_callback (char *buf, int size, int /*rwflag*/, void *userdata)
{
    if (userdata==nullptr)
    {
        buf[0]='\0';
        return 0;
        printf("nopass\n");
        fflush(stdout);
    }
    //printf("Pass :%s / sizebuf : %i / %i\n",(char*)userdata,size,strlen((char*)userdata));
    //fflush(stdout);
    if ((unsigned int)size < strlen((char*)userdata))
        strncpy(buf, (char *)(userdata), size);
    else
        strncpy(buf, (char *)(userdata),strlen((char*)userdata));
    buf[strlen((char*)userdata)] = '\0';
    //printf("Pass :%s / %i\n",buf,strlen(buf));
    //fflush(stdout);
    return(strlen(buf));
}

int SSLCertificates::x509_extension_add(std::string extensionNameI, std::string extensionValI, int extensionCriticalI)
{
    std::string value = (extensionCriticalI == 1)?"critical,":"";
    value += extensionValI;
    X509 *test=X509_new();
    if (test==nullptr) return 2;

    if (this->add_ext_bytxt(test,(char*)extensionNameI.data(),(char*)value.data()) == 0)
    {
        this->get_ssl_errors();
        X509_free(test);
        return 1;
    }
    this->extensionName[this->extensionNum]=extensionNameI;
    this->extensionVal[this->extensionNum]=extensionValI;
    this->extensionCritical[this->extensionNum++]=extensionCriticalI;
    return 0;
}

int SSLCertificates::add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}

int SSLCertificates::add_ext_bytxt(X509 *cert, char* nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    ex = X509V3_EXT_conf(nullptr, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}

int SSLCertificates::mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days)
{
    X509 *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME2 *x509Name;

    if ((pkeyp == nullptr) || (*pkeyp == nullptr))
        {
        if ((pk=EVP_PKEY_new()) == nullptr)
            {
            //abort();
            return(0);
            }
        }
    else
        pk= *pkeyp;

    if ((x509p == nullptr) || (*x509p == nullptr))
        {
        if ((x=X509_new()) == nullptr)
            goto err;
        }
    else
        x= *x509p;

    rsa=RSA_generate_key(bits,RSA_F4,nullptr,nullptr);
    if (!EVP_PKEY_assign_RSA(pk,rsa))
        {
        //abort();
        goto err;
        }
    rsa=nullptr;

    X509_set_version(x,2);
    ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
    X509_gmtime_adj(X509_get_notBefore(x),0);
    X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
    X509_set_pubkey(x,pk);

    x509Name=X509_get_subject_name(x);

    /* This function creates and adds the entry, working out the
     * correct string type and performing checks on its length.
     * Normally we'd check the return value for errors...
     */
    X509_NAME_add_entry_by_txt(x509Name,(const char *)"C",
                MBSTRING_ASC, (const unsigned char *)"UK", -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509Name,(const char *)"CN",
                MBSTRING_ASC, (const unsigned char *)"OpenSSL Group", -1, -1, 0);

    /* Its self signed so set the issuer name to be the same as the
     * subject.
     */
    X509_set_issuer_name(x,x509Name);

    /* Add various extensions: standard extensions */
    this->add_ext(x, NID_basic_constraints, (char*)"critical,CA:TRUE");
    this->add_ext(x, NID_key_usage, (char*)"critical,keyCertSign,cRLSign");

    this->add_ext(x, NID_subject_key_identifier, (char*)"hash");

    /* Some Netscape specific extensions */
    this->add_ext(x, NID_netscape_cert_type, (char*)"sslCA");

    this->add_ext(x, NID_netscape_comment, (char*)"example comment extension");


#ifdef CUSTOM_EXT
    /* to add extension based on existing */
    {
        int nid;
        nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
        X509V3_EXT_add_alias(nid, NID_netscape_comment);
        add_ext(x, nid, "example comment alias");
    }
#endif

    if (!X509_sign(x,pk,EVP_md5()))
        goto err;

    *x509p=x;
    *pkeyp=pk;
    return(1);
err:
    return(0);
}

int SSLCertificates::get_key_type()
{
    if (this->pkey == nullptr)
        return NID_undef;

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    switch (EVP_PKEY_type(EVP_PKEY_id(this->pkey)))
#else
    switch (EVP_PKEY_type(this->pkey->type))
#endif
    {
    case EVP_PKEY_RSA:
        return KeyRSA;
    case EVP_PKEY_DSA:
        return KeyDSA;
    case EVP_PKEY_EC:
        return KeyEC;
    case EVP_PKEY_DH:
        return NID_undef; // TODO : not implemented DH
    }
    return NID_undef;
}

int SSLCertificates::check_key() // TODO DSA and DH
{
    int retcode;
    RSA* rsa;
    DSA* dsa;
    EC_KEY* ec;
    int type=this->get_key_type();
    if (type==NID_undef) return 1;
    switch (type)
    {
    case KeyRSA :
        rsa = EVP_PKEY_get1_RSA(pkey);
        retcode = RSA_check_key(rsa);
        RSA_free(rsa);
        if (retcode ==1) return 0;
        return 1;
    case KeyDSA :
        dsa = EVP_PKEY_get1_DSA(pkey);
        //retcode = DSA_check_key(dsa); TODO : find check key function
        retcode = 0; // Send OK for now
        DSA_free(dsa);
        return retcode;
    /*case EVP_PKEY_DH :    // TODO implement DH
        DH* dh = EVP_PKEY_get1_DH(pkey);
        retcode = DH_check_key(dh);
        DH_free(dh);
        return retcode;*/
    case KeyEC :
        ec = EVP_PKEY_get1_EC_KEY(pkey);
        retcode = EC_KEY_check_key(ec);
        EC_KEY_free(ec);
        if (retcode ==1) return 0;
        return 1;
    default:
        break;

    }
    return 10;
}

int SSLCertificates::check_key_csr_match()
{
    if (this->check_key() != 0)
        return 2;

    int retcode = X509_REQ_verify(this->csr,this->pkey);
    if (retcode == 1)
    {
      return 0;
    }
    return 1;
}

int SSLCertificates::check_key_cert_match()
{
    if (this->check_key() != 0)
        return 2;
    // init context
    SSL_CTX* ctx = SSL_CTX_new( TLSv1_2_client_method()); //  TLSv1_client_method());
    if (ctx==nullptr)
      {
        this->get_ssl_errors();
        return 2;
      }
    // add certificate and key to context
    if (SSL_CTX_use_certificate(ctx, this->x509)!=1)
    {
        this->get_ssl_errors();
        SSL_CTX_free(ctx);
        return 2;
    }
    if (SSL_CTX_use_PrivateKey(ctx, this->pkey)!=1)
    {
        this->get_ssl_errors();
        SSL_CTX_free(ctx);
        return 2;
    }

    if (SSL_CTX_check_private_key(ctx)!=1)
    //int retcode = X509_verify(this->x509, this->pkey);
    {
        this->get_ssl_errors();
        SSL_CTX_free(ctx);
        return 1;
    }
    SSL_CTX_free(ctx);
    return 0;
}
