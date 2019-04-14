#include "cdialogpkcs12.h"
#include "ui_cdialogpkcs12.h"

CDialogPKCS12::CDialogPKCS12(SSLCertificates *Certificate, QString Filename, bool write, CStackWindow *cur_stack, QWidget *parent) :
  QDialog(parent),
  ui(new Ui::CDialogPKCS12)
{
  ui->setupUi(this);

  this->cert=Certificate;
  this->file=Filename;
  this->isWrite=write;
  this->stack=cur_stack;
  // make connection to import cert from stack
  QObject::connect(
        this->stack,SIGNAL(p12_import(CStackWindow::CertData)),
        this,SLOT(stack_cert_selected(CStackWindow::CertData))
  );
  QString value;
  char * certCN=static_cast<char *>(malloc(sizeof(char)*500));
  if (certCN==nullptr)
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
    this->ui->pushButtonImportCert->hide();
    this->ui->pushButtonImportMain->hide();
    this->ui->pushButtonPushAll->hide();
  }
  else
  {
    this->ui->lineEditPassword->hide();
    this->ui->labelPassword->hide();
    this->ui->pushButtonLoadCert->hide();
    this->ui->pushButtonSaveAs->hide();
    this->ui->pushButtonSelectFromStack->hide();
    this->ui->lineEditFriendlyName->setText(cert->get_pkcs12_name());

     for (int i=0;i<cert->get_pkcs12_certs_num();i++)
     {
       std::string cn=cert->get_pkcs12_certs_CN(static_cast<unsigned int>(i));
       QListWidgetItem *line=new QListWidgetItem(QString::fromStdString(cn));
       ui->listWidgetCA->addItem(line);
     }

  }
}

CDialogPKCS12::~CDialogPKCS12()
{
  delete ui;
}

void CDialogPKCS12::stack_cert_selected(CStackWindow::CertData certificate)
{
  SSLCertificates *newCA = new SSLCertificates();
  switch (newCA->set_cert_PEM(certificate.certificate.toLocal8Bit(),""))
  {
    case 1://Error parsing cert
    case 2://password (???)
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

  if (this->cert->add_pkcs12_ca(certificate.certificate.toLocal8Bit()) != 0)
  {
    QMessageBox::critical(this,tr("Error"),tr("Error loading cert\nLoad with main window for more info"));
   }
  delete newCA;
  return;
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
  QString filename;
  FILE* file;
  int fileOpen;
  do
  {
    // Get filename
    filename=QFileDialog::getSaveFileName(this, "Export to pkcs12", "",
                       tr("pkcs12 (*.p12);;Any (*.*)"));
    if (filename=="")
    {
        return;
    }
    if ( (fileOpen=fopen_s(&file,filename.toLocal8Bit().data(),"wb")) != 0)
    {
        QMessageBox::warning(this,tr("Error opening file"),tr("Cannot open file : ")+filename);
    }
  }
  while( fileOpen != 0);

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

void CDialogPKCS12::on_pushButtonSelectFromStack_clicked()
{
    this->stack->pkcs12Selection(true);
    this->stack->show();
}

void CDialogPKCS12::on_pushButtonPushAll_clicked()
{
    char buffer[MAX_CERT_SIZE];
    for (int i=0;i< this->ui->listWidgetCA->count();i++)
    {
      CStackWindow::CertData curcert;
      this->cert->get_pkcs12_certs_pem(static_cast<unsigned int>(i),buffer,MAX_CERT_SIZE);
      curcert.certificate = QString::fromLocal8Bit(buffer);
      curcert.cert_type=CStackWindow::certificate;
      curcert.name=this->ui->listWidgetCA->item(i)->text();
      curcert.key_type=SSLCertificates::KeyNone;
      this->stack->push_cert(&curcert);
    }
    this->ui->pushButtonPushAll->setDisabled(true);
}
