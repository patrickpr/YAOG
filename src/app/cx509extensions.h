#ifndef CX509EXTENSIONS_H
#define CX509EXTENSIONS_H

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/opensslv.h>

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <tuple>
#include <map>


class cGenExtension
{
public:
  /**** Structures ****/
  typedef struct NIDName { int NID;std::string name; std::string longName;} NIDName;
  /**** Members ****/
  int NID;
  bool isSet;
  bool critical;
  /**** Functions ****/
  cGenExtension();
  /**
   * @brief clear : disable extension
   */
  void clear();
  /**
   * @brief getIndexfromNID : get index in array structure of NIDName by NID
   * @param NID
   * @return index
   * @throw std::char if not found.
   */
  int getIndexfromNID(int NID);

  void setCritical(bool critical) {this->critical = critical;}
  /**
   * @brief getExtbyNID : extract extension for local NID and set critical value in class member.
   * @param cert certificate to extract extension from
   * @return extension
   * @throw std::string if extension not found.
   */
  X509_EXTENSION *getExtbyNID(X509 *cert);

  virtual bool decode (X509 *cert);
  virtual std::string print();
  /**** Data ******/
  std::array <NIDName,9> generalNameTypes =
  { {{ GEN_OTHERNAME    , "", "otherName"},
    { GEN_EMAIL 	, "EMAIL", "rfc822Name"},
    { GEN_DNS 		, "DNS", "dNSName"},
    { GEN_X400 	, "", "x400Address"},
    { GEN_DIRNAME 	, "", "directoryName"},
    { GEN_EDIPARTY 	, "", "ediPartyName"},
    { GEN_URI 		, "URI", "uniformResourceIdentifier"},
    { GEN_IPADD 	, "IP", "iPAddress"},
    { GEN_RID 		, "", "registeredID"}}
  };

  std::array <NIDName,8> ns_cert_type_table = { {
    {0 , "client", "SSL Client"},
    {1 , "server", "SSL Server"},
    {2 , "email", "S/MIME"},
    {3 , "objsign", "Object Signing"},
    {4 , "reserved", "Unused"},
    {5 , "sslCA", "SSL CA"},
    {6 , "emailCA", "S/MIME CA"},
    {7 , "objCA", "Object Signing CA"},
  }};

  std::array <NIDName,9> key_usage_type_table = {{
    {0 , "digitalSignature", "Digital Signature"},
    {1 , "nonRepudiation", "Non Repudiation"},
    {2 , "keyEncipherment", "Key Encipherment"},
    {3 , "dataEncipherment", "Data Encipherment"},
    {4 , "keyAgreement", "Key Agreement"},
    {5 , "keyCertSign", "Certificate Sign"},
    {6 , "cRLSign", "CRL Sign"},
    {7 , "encipherOnly", "Encipher Only"},
    {8 , "decipherOnly", "Decipher Only"}
  }};

  std::array <NIDName,10> x509ExtKeyUsageList ={{
     {NID_server_auth,"serverAuth","TLS Web Server Authentication"},
     {NID_client_auth,"clientAuth","TLS Web Client Authentication"},
     {NID_email_protect,"emailProtection","E-mail Protection"},
     {NID_code_sign,"codeSigning","Code Signing"},
     {NID_ms_sgc,"msSGC","Microsoft Server Gated Crypto"},
     {NID_ns_sgc,"nsSGC","Netscape Server Gated Crypto"},
     {NID_OCSP_sign,"OCSPSigning","OCSP Signing"},
     {NID_time_stamp,"timeStamping","Time Stamping"},
     {NID_dvcs,"DVCS","dvcs"},
     {NID_anyExtendedKeyUsage,"anyExtendedKeyUsage","Any Extended Key Usage"}
  }};

protected:
};

class cGeneralName
{
public:
  cGeneralName();
  ~cGeneralName();

  GENERAL_NAME *getGN();

  GENERAL_NAME* data;

  void setIA5String(int type,std::string val);

  /**** Structures and data ****/

  typedef struct genName { int NID;std::string name; std::string longName;} genName;
  std::array <genName,9> generalNameTypes =
  { {{ GEN_OTHERNAME    , "", "otherName"},
    { GEN_EMAIL 	, "EMAIL", "rfc822Name"},
    { GEN_DNS 		, "DNS", "dNSName"},
    { GEN_X400          , "", "x400Address"},
    { GEN_DIRNAME 	, "", "directoryName"},
    { GEN_EDIPARTY 	, "", "ediPartyName"},
    { GEN_URI 		, "URI", "uniformResourceIdentifier"},
    { GEN_IPADD 	, "IP", "iPAddress"},
    { GEN_RID 		, "", "registeredID"}}
  };
};

class cSubjAltName : public cGenExtension
{
public:
  cSubjAltName();
  /**
   * @brief get
   * @param type : vector of generalNameTypes
   * @param name : corresponding vector of strings
   * @param critical
   * @return
   */
  bool get(std::vector<int>& type, std::vector<std::string>& name, bool& critical);
  /**
   * @brief add
   * @param type : one of generalNameTypes
   * @param name
   * @param critical
   */
  void add(int type, std::string name);
  /**
   * @brief clearSubjectAltName : clear values of SAN
   */
  void clear();
  /**
   * @brief print
   * @return human readable string of extension
   */
  std::string print();
  /**
   * @brief decode : get extension in cert if available and extract data in object.
   * @param cert
   * @return false if not found / error
   */
  bool decode(X509 * cert);
  std::string name = SN_subject_alt_name;
  std::string longName = LN_subject_alt_name;
  int NID = NID_subject_alt_name;
  std::string examples = "DNS:<site>,URI:https://<site>,email:<mail>,IP:<IP4/6>";
  std::array <NIDName,9>& typeList = generalNameTypes;

private:
  /* subjectAltName vector <int NID, string Value> , ex <GEN_DNS,"www.site.com"> */
  std::vector <NIDName> subjectAltName;
};

class cBasicConst : public cGenExtension
{
public:
  cBasicConst();
  /**
   * @brief get
    * @param isCA
    * @param pathLen : if 0 then not set
    * @param critical
   * @return false if not set
   */
  bool get(bool& isCA, int& pathLen, bool& critical);
  /**
   * @brief set
    * @param isCA
    * @param pathLen : 0 if not set
   * @param critical
   */
  void set(bool isCA, int pathLen, bool critical);
  /**
   * @brief clear : clear values of BasicConst
   */
  void clear();
  /**
   * @brief print
   * @return human readable string of extension
   */
  std::string print();
  /**
   * @brief decode : get extension in cert if available and extract data in object.
   * @param cert
   * @return false if not found / error
   */
  bool decode(X509 * cert);

  std::string name = SN_basic_constraints;
  std::string longName = LN_basic_constraints;
  int NID = NID_basic_constraints;
  std::string examples = "CA:TRUE,CA:FALSE,pathlen:<num>";

private:
  bool isCA;
  int pathLen;
};


class cX509Extensions
{
public:
  cX509Extensions(X509 * cert = nullptr);

  std::string t = SN_subject_alt_name;
  cSubjAltName* subjectAltName;
  cBasicConst* basicConstraints;

  std::array<cGenExtension*,2> allExtensions = {
    (cGenExtension *)& subjectAltName,
    (cGenExtension *)& basicConstraints}
  ;
  // functions
  /**
   * @brief decodeCert : decode all possible extensions from cert
   * @param cert
   */
  void decodeCert(X509 * cert);

  /**
   * @brief printAll
   * @return string for every defined extension
   */
  std::vector<std::string> printAll();
/***** Structures ******/
  typedef struct x509Extension {
      std::string name; //!< Name of extension
      std::string longName; //!< Long name of extension
      int NID; //!< NID of extension
      std::string values; //!< examples of possible values comma separated
  } x509Extension; //!< Structure for x509 extension array

  typedef struct NIDName { int NID;std::string name; std::string longName;} NIDName;

/******* Extensions & params list ***********/

   std::array <x509Extension,9> X509ExtensionList =
  {
      {{SN_basic_constraints,LN_basic_constraints,NID_basic_constraints,"CA:TRUE,CA:FALSE,pathlen:<num>"},
      {SN_key_usage,LN_key_usage,NID_key_usage,"digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign,encipherOnly,decipherOnly"},
      {SN_subject_alt_name,LN_subject_alt_name,NID_subject_alt_name,"DNS:<site>,URI:https://<site>,email:<mail>,IP:<IP4/6>"},
      {SN_crl_distribution_points,LN_crl_distribution_points,NID_crl_distribution_points,"URI:https://<site>"},
      {SN_ext_key_usage,LN_ext_key_usage,NID_ext_key_usage,"serverAuth,clientAuth,codeSigning,emailProtection,timeStamping,OCSPSigning,ipsecIKE,msCodeInd,msCodeCom,msCTLSign,msEFS"},
      {SN_subject_key_identifier,LN_subject_key_identifier,NID_subject_key_identifier,"<key>"},
      {SN_authority_key_identifier,LN_authority_key_identifier,NID_authority_key_identifier,"keyid:<key>"},
      {SN_certificate_policies,LN_certificate_policies,NID_certificate_policies,"1.2.4.5"},
      {SN_policy_constraints,LN_policy_constraints,NID_policy_constraints,"requireExplicitPolicy:<num>,inhibitPolicyMapping:<num>"}}
  };

protected:

  /* keyUsage : bit string in two bytes */
  int keyUsage[2];
  bool keyUsageCrit;

};

#endif // CX509EXTENSIONS_H
