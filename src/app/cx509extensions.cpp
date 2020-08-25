#include "cx509extensions.h"

cX509Extensions::cX509Extensions(X509 *cert)
{
  this->subjectAltName = new cSubjAltName();
  this->basicConstraints = new cBasicConst();

  if (cert != nullptr)
  {
    this->decodeCert(cert);
  }
}

void cX509Extensions::decodeCert(X509 *cert)
{
  this->subjectAltName->decode(cert);
  this->basicConstraints->decode(cert);
}

std::vector<std::string> cX509Extensions::printAll()
{
  std::vector<std::string> vector;
  std::string output;

  output = this->subjectAltName->print();
  if (output.size()>0) vector.push_back(output);

  output = this->basicConstraints->print();
  if (output.size()>0) vector.push_back(output);
  int i =V_ASN1_GENERALSTRING;
  return vector;
}

/***************** Generic Extension class **************/

cGenExtension::cGenExtension()
{
  this->isSet=false;
}

void cGenExtension::clear()
{
  this->isSet = false;
  this->critical = false;
}

int cGenExtension::getIndexfromNID(int NID)
{
  for (size_t i=0;i<this->generalNameTypes.size();i++)
  {
    if (NID == this->generalNameTypes[i].NID) return i;
  }
  throw "Unkown NID";
}

X509_EXTENSION * cGenExtension::getExtbyNID(X509 *cert)
{
  int loc;
  X509_EXTENSION * extension;

  loc = X509_get_ext_by_NID(cert,this->NID,-1); // get location of extension
  if (loc == -1) throw "NID not found : " + std::to_string(this->NID); // extension does not exists
  extension = X509_get_ext(cert, loc);
  if (extension == nullptr) throw "Extension not found index : " + std::to_string(loc);

  this->critical = (X509_EXTENSION_get_critical(extension)==1) ? true : false;

  return extension;
}



/**************** Subject Alternate Name class ***************/

cSubjAltName::cSubjAltName() : cGenExtension()
{
  this->subjectAltName.clear();
}

bool cSubjAltName::get(std::vector<int> &type, std::vector<std::string> &name, bool &critical)
{
  if (!this->isSet) return false;
  critical = this->critical;
  for (auto x: this->subjectAltName )
  {
    type.push_back(x.NID);
    name.push_back(x.name);
  }
  return true;
}

void cSubjAltName::add(int type, std::string name)
{
  this->isSet=true;

  NIDName newSAN= {type,name,""};
  this->subjectAltName.push_back(newSAN);

}

void cSubjAltName::clear()
{
  this->subjectAltName.clear();
  cGenExtension::clear();
}

std::string cSubjAltName::print()
{
  std::string output= "";

  for (auto x: this->subjectAltName )
  {
    if (output.size()>0) output += ',';
    try {
      output += this->generalNameTypes[this->getIndexfromNID(x.NID)].name + ':' + x.name;
    }
    catch (std::string err)
    {
       output += err;
    }
  }

  return this->name + ((this->critical) ? "critical":"") + output;
}

bool cSubjAltName::decode(X509 *cert)
{
  X509_EXTENSION * extension;

  try { extension = this->getExtbyNID(cert); }
  catch (std::string) { return false; }

  GENERAL_NAMES *names = nullptr;
  names = (GENERAL_NAMES *) X509V3_EXT_d2i(extension);
  if (names == nullptr) return false;

  int numAltNames=sk_GENERAL_NAME_num(names);
  for (int i=0;i<numAltNames;i++)
  {
     GENERAL_NAME *currentName = sk_GENERAL_NAME_value(names, i);

     const char *AltName = nullptr;
     switch (currentName->type)
     {
       break;
       case GEN_DNS:
         AltName = (const char *) ASN1_STRING_get0_data(currentName->d.dNSName);
       break;
       case GEN_URI:
         AltName = (const char *) ASN1_STRING_get0_data(currentName->d.uniformResourceIdentifier);
       break;
       case GEN_IPADD:
         AltName = (const char *) ASN1_STRING_get0_data(currentName->d.iPAddress);
       break;
       default:
         AltName = "Unsupported ASN1 TYPE";
     }
     this->add(currentName->type,std::string(AltName));
  }
  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free); // Free stack
  return true;
}

/**************** Basic Constraints class ***************/

cBasicConst::cBasicConst(): cGenExtension()
{
  this->pathLen=0;
}

bool cBasicConst::get(bool &isCA, int &pathLen, bool &critical)
{
  if (!this->isSet) return false;
  isCA=this->isCA;
  pathLen = this->pathLen;
  critical = this->critical;
  return true;
}

void cBasicConst::set(bool isCA, int pathLen, bool critical)
{
  this->isSet=true;
  this->isCA = isCA;
  this->pathLen = pathLen;
  this->critical=critical;
}

void cBasicConst::clear()
{
  cGenExtension::clear();
  this->pathLen=0;
}

std::string cBasicConst::print()
{
  if (!this->isSet) return "";
  std::string output= "CA:";
  output += (this->isCA) ? "TRUE" : "FALSE";
  output += (this->pathLen == 0) ? "" : ",pathlen:" + std::to_string(this->pathLen);

  return this->name + ((this->critical) ? "critical":"") + output;
}

bool cBasicConst::decode(X509 *cert)
{
  X509_EXTENSION * extension;

  try { extension = this->getExtbyNID(cert); }
  catch (std::string) { return false; }

  BASIC_CONSTRAINTS *bs = (BASIC_CONSTRAINTS *) X509V3_EXT_d2i(extension);
  if (bs == nullptr) return false;

  this->isCA = (bs->ca == 255) ? true : false;

  this->pathLen = ASN1_INTEGER_get(bs->pathlen);

  BASIC_CONSTRAINTS_free(bs);
  return true;
}




/**************** General Name class ***************/

cGeneralName::cGeneralName()
{
  this->data = nullptr;
}

cGeneralName::~cGeneralName()
{
  if (this->data != nullptr)
  {
    GENERAL_NAME_free(this->data);
  }
}

GENERAL_NAME *cGeneralName::getGN()
{
  if (this->data == nullptr)
  {
    data = GENERAL_NAME_new();
  }
  return data;
}

void cGeneralName::setIA5String(int type, std::string val)
{
  GENERAL_NAME* gn = GENERAL_NAME_new();
  switch (type)
  {
    case GEN_EMAIL:
      X509V3_EXT_METHOD * test;
      //test->v
  }
}

