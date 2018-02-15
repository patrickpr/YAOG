#include "cdialogpkcs12.h"
#include "ui_cdialogpkcs12.h"

CDialogPKCS12::CDialogPKCS12(SSLCertificates *Certificate, QString Filename, bool write, QWidget *parent) :
  QDialog(parent),
  ui(new Ui::CDialogPKCS12)
{
  ui->setupUi(this);

  this->cert=Certificate;
  this->file=Filename;
  this->isWrite=write;

  QString value;
  char * certCN=(char*)malloc(sizeof(char)*500);
  if (certCN==NULL)
    {
      ui->lineEditCertificate->setText("MEMORY ERROR!!");
      return;
    }
   if (cert->get_cert_CN(certCN,500) != 0)
     {
       value=tr("Error getting CN");
     }
   else
     {
       value=QString::fromLocal8Bit(certCN);
     }
   ui->lineEditCertificate->setText(value);

  if (this->isWrite)
  {
    ui->pushButtonImportCert->hide();
    ui->pushButtonImportMain->hide();
  }
  else
  {
    ui->lineEditPassword->hide();
    ui->labelPassword->hide();
    ui->pushButtonLoadCert->hide();
    ui->pushButtonSaveAs->hide();
    ui->lineEditFriendlyName->setText(cert->get_pkcs12_name());

     for (int i=0;i<cert->get_pkcs12_certs_num();i++)
     {
       std::string cn=cert->get_pkcs12_certs_CN(i);
       QListWidgetItem *line=new QListWidgetItem(QString::fromStdString(cn));
       ui->listWidgetCA->addItem(line);
     }

  }
}

CDialogPKCS12::~CDialogPKCS12()
{
  delete ui;
}

void CDialogPKCS12::on_pushButtonLoadCert_clicked()
{
  QString certPem;

  QString filename=QFileDialog::getOpenFileName(this, "Load certificate", "",
                     tr("Cert (*.crt *.pem *.cer *.csr);;Any (*.*)"));
  if (filename=="") return;
  QFile file( filename );
  if (! file.open( QIODevice::ReadOnly | QIODevice::Text))
  {
      QMessageBox::warning(this,tr("Error"),tr("Cannot read file"));
      return;
  }
  QTextStream out(&file);
  certPem = out.readAll();
  file.close();

  SSLCertificates *newCA = new SSLCertificates();
  switch (newCA->set_cert_PEM(certPem.toLatin1().data(),""))
  {
    case 1://Error parsing cert
    case 2://password (IN P12 ???)
      QMessageBox::critical(this,tr("Error"),tr("Error loading cert\nLoad with main window for more info"));
      delete newCA;
      return;
  }
  char CN[200];
  if (newCA->get_cert_CN(CN,200) != 0)
  {
    QMessageBox::critical(this,tr("Error"),tr("Error getting CN of cert"));
    delete newCA;
    return;
  }
  QListWidgetItem *line=new QListWidgetItem(QString::fromLocal8Bit(CN));
  ui->listWidgetCA->addItem(line);

  if (this->cert->add_pkcs12_ca(certPem.toLatin1().data()) != 0)
  {
    QMessageBox::critical(this,tr("Error"),tr("Error loading cert\nLoad with main window for more info"));
   }
  delete newCA;
  return;
}

void CDialogPKCS12::on_pushButtonImportMain_clicked()
{
  emit DlgPKCS12_Finished(false,true,-1);
}

void CDialogPKCS12::on_pushButtonImportCert_clicked()
{

  if (ui->listWidgetCA->currentRow() == -1)
  {
      QMessageBox::warning(this,tr("No row selected"),tr("Select one certificate"));
  }
  else
  {
    emit DlgPKCS12_Finished(false,false,ui->listWidgetCA->currentRow());
  }
}

void CDialogPKCS12::on_pushButtonSaveAs_clicked()
{
  // Get filename
  QString filename=QFileDialog::getSaveFileName(this, "Export to pkcs12", "",
                     tr("pkcs12 (*.p12);;Any (*.*)"));
  if (filename=="")
  {
      return;
  }

  FILE* file;

  file=fopen(filename.toLocal8Bit().data(),"wb");

  QString name=ui->lineEditFriendlyName->text();
  QString pass=ui->lineEditPassword->text();
  ui->lineEditPassword->setText("                ");
  ui->lineEditPassword->setText("");
  switch (this->cert->save_to_pkcs12(file,name.toLocal8Bit().data(),pass.toLocal8Bit().data()))
  {
    case 0:
      QMessageBox::information(this,tr("Saved"),tr("File saved"));
      emit DlgPKCS12_Finished(true,false,0);
      break;
    case 1:  QMessageBox::warning(this,tr("Error"),tr("Error creating p12"));
      break;
    case 2: QMessageBox::warning(this,tr("Error"),tr("Error saving file"));
      break;
  }
  pass="                  ";
  fclose(file);
}

void CDialogPKCS12::on_pushButtonCancel_clicked()
{
    emit DlgPKCS12_Finished(true,false,0);
}