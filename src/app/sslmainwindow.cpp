#include "sslmainwindow.h"
#include "ui_sslmainwindow.h"

QString SSLMainWindow::CBdata="";
QMutex SSLMainWindow::CBMutex;


/**
TODO
ASSERT: "refCount.load() >= 0" in file thread\qmutex_p.h, line 101
 */

SSLWorker::SSLWorker(SSLCertificates* newcert)
{
    this->Cert=newcert;
}

SSLWorker::~SSLWorker()
{

}

SSLMainWindow::SSLMainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::SSLMainWindow)
{
    // Add icons and images
    QIcon icon(":/icons/res/lock.ico");
    this->setWindowIcon(icon);
    ui->setupUi(this);
    /* Set default params */
    ui->comboBoxKeySize->addItem("1024",1024);
    ui->comboBoxKeySize->addItem("2048",2048);
    ui->comboBoxKeySize->addItem("4096",4096);
    ui->comboBoxKeySize->addItem("8192",8192);

    ui->comboBoxCertGen->addItem(tr("CSR + key"),1);
    ui->comboBoxCertGen->addItem(tr("Autosign + key"),2);
    ui->comboBoxCertGen->addItem(tr("CSR (existing key)"),3);

    // Initialise the CertificateList QList
    CertData* current=new CertData;
    current->certificate=current->CSR=current->key="";
    current->name="Default";
    //this->CertificateList.append(current);

    //SSLMainWindow::CBMutex.unlock(); // Hope there is only one instance of SSLMainWindow....
    SSLMainWindow::CBdata="";

    this->cert_output_type=OUTPUT_TYPE_CERT;
    this->ui->radioButtonDisplayCSR->setChecked(false);
    this->ui->radioButtonDisplayCertificate->setChecked(true);

    // Get SSL digests, ciphers,etc...
    this->init_cert();
    for (int i=0; i< this->Cert->digestsListNum;i++)
    {
        ui->comboBoxCertDigest->addItem(this->Cert->digestsList[i],i);
    }
    for (int i=0; i< this->Cert->ciphersListNum;i++)
    {
        ui->comboBoxKeyCipher->addItem(this->Cert->ciphersList[i],i);
    }
    for (int i=0; i< this->Cert->keyTypeListNum;i++)
    {
        ui->comboBoxKeyType->addItem(this->Cert->keyTypeList[i],i);
    }

    // Create Extension table
    this->ui->TWExtensions->setColumnCount(4);
    this->ui->TWExtensions->setRowCount(0);
    this->ui->TWExtensions->setColumnWidth(0,30);
    this->ui->TWExtensions->setColumnWidth(2,30);
    this->ui->TWExtensions->setHorizontalHeaderLabels(
                QString("Del;Name;Crit;Value").split(";"));
    extensionElmtMapIndex=0;

    extensionSigMap = new QSignalMapper(this);
    QObject::connect(extensionSigMap, SIGNAL(mapped(int)),
                this, SLOT(extension_button_del_on_clicked(int)));

    //extensionElmt *basic=this->addExtensionElmt("basicConstraints",87,false,"CA:FALSE");
    //addExtensionLine(basic);

    /* Load settings */
    QCoreApplication::setOrganizationName("YAOG");
    QCoreApplication::setOrganizationDomain("");
    QCoreApplication::setApplicationName("YAOGApp");

    this->get_settings("default");    
    this->check_updates();
    srand (time(nullptr));
}

SSLMainWindow::extensionElmt *SSLMainWindow::addExtensionElmt(QString label,unsigned int NID,bool critical, QString value)
{ // TODO : error check with memory alloc
    extensionElmt* element=new extensionElmt;
    element->label=label;
    element->labelWidget = new QLabel(label,this);
    element->labelWidget->setText(element->label);
    // Delete button (centered)
    element->deleteBtn = new QPushButton(this);
    element->deleteBtn->setText("X");
    element->deleteBtn->setFixedWidth(20);
    element->deleteBtn->setFixedHeight(20);
    element->deleteBtnwdg = new QWidget;
    element->deleteBtnwdglayout = new QHBoxLayout(element->deleteBtnwdg);
    element->deleteBtnwdglayout->addWidget(element->deleteBtn);
    element->deleteBtnwdglayout->setAlignment( Qt::AlignCenter );
    element->deleteBtnwdglayout->setContentsMargins(0, 0, 0, 0);
    element->deleteBtnwdg->setLayout(element->deleteBtnwdglayout);
    // Critial checkbox (centered)
    element->critical=new QCheckBox("",this);
    element->critical->setChecked(critical);
    element->criticalwdg = new QWidget;
    element->criticallayout = new QHBoxLayout(element->criticalwdg);
    element->criticallayout->addWidget(element->critical);
    element->criticallayout->setAlignment( Qt::AlignCenter );
    element->criticallayout->setContentsMargins(0, 0, 0, 0);
    element->criticalwdg->setLayout(element->criticallayout);
    // Set value as lineEdit and set NID
    element->value=new QLineEdit(value,this);
    element->NID=NID;
    element->row=-1;
    element->index=this->extensionElmtMapIndex++;
    this->extensionList.append(element);
    return element;
}

void SSLMainWindow::addExtensionLine(extensionElmt *elmt)
{
    int currentRow=this->ui->TWExtensions->rowCount();
    this->ui->TWExtensions->setRowCount(currentRow+1);
    //currentRow--;
    elmt->row=currentRow;
    // TODO : connect delete button to function.
    this->ui->TWExtensions->setCellWidget(currentRow,0,elmt->deleteBtnwdg);
    this->ui->TWExtensions->setCellWidget(currentRow,1,elmt->labelWidget);
    this->ui->TWExtensions->setCellWidget(currentRow,2,elmt->criticalwdg);
    this->ui->TWExtensions->setCellWidget(currentRow,3,elmt->value);
    this->ui->TWExtensions->resizeColumnsToContents();
    this->extensionSigMap->setMapping(elmt->deleteBtn, elmt->index);
    QObject::connect(elmt->deleteBtn, SIGNAL(clicked()),
                     this->extensionSigMap, SLOT(map()));

    return;
}

SSLMainWindow::~SSLMainWindow()
{
    delete ui;
}

void SSLMainWindow::CB_add_data(char* data) {
    //qDebug("addind data");
    SSLMainWindow::CBMutex.lock();
    SSLMainWindow::CBdata+=data;
    SSLMainWindow::CBMutex.unlock();
    //qDebug("addind done");
}

QString SSLMainWindow::CB_read_data() {
    QString ret;
    //qDebug("read data");
    SSLMainWindow::CBMutex.lock();
    ret=CBdata;
    SSLMainWindow::CBdata="";
    SSLMainWindow::CBMutex.unlock();
    //qDebug("read done");
    return ret;
}

void SSLMainWindow::create_async_dialog(QString title)
{
    // Open output dialog in modal but non blocking
    this->DlgGenerateKey = new DialogGenerateKey(title,this);
    DlgGenerateKey->setModal( true );
    DlgGenerateKey->open();

    // Add conection to display output text
    QObject::connect(this, SIGNAL(add_text_output(QString)),
                     DlgGenerateKey, SLOT(add_text_output(QString)));
    QObject::connect(this, SIGNAL(finished_calc()),
                     DlgGenerateKey, SLOT(finished_calc()));
    QObject::connect(DlgGenerateKey, SIGNAL(btn_abort_pressed()),
                     this, SLOT(DlgGenerateKeyAbort()));

    // Set callback
    this->Cert->set_display_callback(&SSLMainWindow::CB_add_data);
    // Set timer to check Callback data
    this->timer=new QTimer(this);
    connect(this->timer, SIGNAL(timeout()), this, SLOT(read_callback_data()));
    this->timer->start(300);

    // Create worker thread
    this->SSLthread = new QThread(this);
    this->sslworker = new SSLWorker(this->Cert);
    this->sslworker->moveToThread(SSLthread);
    QObject::connect(this->sslworker, SIGNAL(error(QString)), this, SLOT(DlgGenerateKeyError(QString)));
    QObject::connect(this->sslworker, SIGNAL(finished()),    this->SSLthread, SLOT(quit()));
    QObject::connect(this->sslworker, SIGNAL(finished()),    this->sslworker, SLOT(deleteLater()));
    QObject::connect(this->SSLthread, SIGNAL(finished()),    this->SSLthread, SLOT(deleteLater()));
}

void SSLMainWindow::flush_async_dialog()
{
    delete this->timer;
    this->read_callback_data(); // finish reading pipe
    emit add_text_output("Waiting for process to finish...\n");
    //just in case, wait for everything to finish
    if (this->SSLthread != NULL)
    {
      this->SSLthread->wait(1000);
    }
}

void SSLMainWindow::close_async_dialog() {
    // Tell dialog that eveything is done
    emit  finished_calc();
}

void SSLMainWindow::read_callback_data() {
    QString output=SSLMainWindow::CB_read_data();
    if (output.length() != 0) {
        emit add_text_output(output);
    }
}

void SSLMainWindow::init_cert()
{
    try { this->Cert=new SSLCertificates(); }
    catch (int e)
    {
        QMessageBox msgBox;
        if (e==10)  msgBox.setText("Error initializing key(s) : program will end");
        if (e==20)  msgBox.setText("Error initializing certificate : program will end");
        msgBox.exec();
        exit(1);
    }
}

void SSLMainWindow::display_ssl_err(QString message)
{
    char ErrorMsg[2000];
    this->Cert->print_ssl_errors(ErrorMsg,2000);
    DialogSSLErrors * ErrDlg=new DialogSSLErrors (message,ErrorMsg,this);
    ErrDlg->setModal(true);
    ErrDlg->exec();
    delete ErrDlg;
}

/*************************** Certificate buttons and utilities ************************/

void SSLMainWindow::on_pushButtonEnableDaysLine_clicked()
{
    this->ui->lineEditCertDays->setEnabled(true);
    this->ui->pushButtonEnableDaysLine->setEnabled(false);
}

void SSLMainWindow::on_toolButtonCertValidity_clicked()
{
    DialogCertDate *Dialog = new DialogCertDate(this);
    QObject::connect(Dialog, SIGNAL(DlgCertDateAccept(QDateTime, QDateTime)),
                     this, SLOT(DlgCertDateAccept(QDateTime, QDateTime)));
    if (Dialog->exec() == QDialog::Accepted)
    {
        this->ui->lineEditCertDays->setEnabled(false);
        this->ui->pushButtonEnableDaysLine->setEnabled(true);
    }
    else
    {
        this->ui->lineEditCertDays->setEnabled(true);
        this->ui->pushButtonEnableDaysLine->setEnabled(true);
    }
}

int SSLMainWindow::read_cert_pem_to_openssl()
{
    int retcode=1;
    // Read content of textEditKey and put it in a Qchar* array
    QByteArray QBskey=this->ui->textEditCert->toPlainText().toLocal8Bit();

    // Put the cert/csr in openssl structure
    if ( this->ui->radioButtonDisplayCertificate->isChecked() )
        retcode=this->Cert->set_cert_PEM(QBskey.data(),NULL);
    if (this->ui->radioButtonDisplayCSR->isChecked())
        retcode=this->Cert->set_csr_PEM(QBskey.data(),NULL);
    if (retcode==1) // Error parsing cert
    {
        return 1;
    }
    if (retcode==2) // Password needed : ask for one
    {
        bool ok=true;
        QString password;
        password=QInputDialog::getText(this, tr("Password needed to decrypt certificate"),
                                           tr("Password to decrypt:"), QLineEdit::Password,
                                           "", &ok);
        if (!password.isEmpty() && ok)
        {
            if (password.toLatin1().size() > PASSWORD_MAX_LENGTH) exit (2);

            if ( this->ui->radioButtonDisplayCertificate->isChecked() )
                retcode=this->Cert->set_cert_PEM(QBskey.data(),password.toLocal8Bit().data());
            if (this->ui->radioButtonDisplayCSR->isChecked())
                retcode=this->Cert->set_csr_PEM(QBskey.data(),password.toLocal8Bit().data());
        }
        password="00000000000000";
        if (retcode!=0)// User cancel / empty pass / wrong pass
            return 1;
    }
    return 0;
}

void SSLMainWindow::DisplayCert()
{
    int retcode=1;
    // Read cert from GUI to openssl structure
    switch (this->read_cert_pem_to_openssl())
    {
    case 1: {
        this->display_ssl_err(tr("Error parsing certificate"));
        return;
    }
    case 2: //maybe blame user another time for forgetting the password ?
        this->display_ssl_err(tr("Error parsing certificate"));
        return;
    }

    // Read cert from openssl strcture to human readable format.
    if ( this->ui->radioButtonDisplayCertificate->isChecked() )
        retcode=this->Cert->get_cert_HUM(this->buffer,MAX_CERT_SIZE);
    if (this->ui->radioButtonDisplayCSR->isChecked())
        retcode=this->Cert->get_csr_HUM(this->buffer,MAX_CERT_SIZE);
    switch (retcode)
    {
    case 1:
        this->display_ssl_err(tr("Copy error in SSL"));
        return;
    case 2:
        this->display_ssl_err(tr("Buffer too small (blame dev)"));
        return;
    case 3:
        this->display_ssl_err(tr("SSL Error writing PEM"));
        return;
    }

    // Show key (reuse error dialog...)
    DialogSSLErrors * ErrDlg=new DialogSSLErrors (tr("Certificate Display"),this->buffer,this);
    ErrDlg->setWindowTitle(tr("Display"));
    ErrDlg->setModal(true);
    ErrDlg->exec();
    // cleanup
    delete ErrDlg;
    return;
}

void SSLMainWindow::on_pushButtonGenerateCert_clicked()
{
    QString serial;
    bool ok;
    unsigned int serialnum;
    int i;
    /* First create cert object */
    this->init_cert();

    QString digest=this->ui->comboBoxCertDigest->currentText();
    if (this->Cert->set_digest(digest.toLatin1().data()) !=0)
    {
        this->display_ssl_err(tr("Unknown Digest"));
        delete this->Cert;
        return;
    }
    if (this->Cert->set_object(
                (unsigned const char*)this->ui->lineEditCertCN->text().toLatin1().data(),
                (unsigned const char*)this->ui->lineEditCertC->text().toLatin1().data(),
                (unsigned const char*)this->ui->lineEditCertS->text().toLatin1().data(),
                (unsigned const char*)this->ui->lineEditCertL->text().toLatin1().data(),
                (unsigned const char*)this->ui->lineEditCertO->text().toLatin1().data(),
                (unsigned const char*)this->ui->lineEditCertOU->text().toLatin1().data(),
                (unsigned const char*)this->ui->lineEditCertEmail->text().toLatin1().data()
        ) != 0 )
    {
        this->display_ssl_err(tr("Error in subject"));
        delete this->Cert;
        return;
    }

    for (i=0;i<this->extensionList.count();i++)
    {
        std::string label=this->extensionList.at(i)->label.toLocal8Bit().data();
        std::string value=this->extensionList.at(i)->value->text().toLocal8Bit().data();
        int crit=(this->extensionList.at(i)->critical->isChecked())?1:0;
        if (this->Cert->x509_extension_add(label,value,crit) != 0)
        {
            this->display_ssl_err(tr("Error in extension: ")+label.data());
            delete this->Cert;
            return;
        }
    }

    switch (this->ui->comboBoxCertGen->currentIndex())
    {
    case 0: //CSR + key
        // Set Key params
        if (this->get_key_param()!=0)
        {
            QMessageBox::warning(this,tr("Error"),tr("Error in Key Param"));
            delete this->Cert;
            return;
        }
        // Create async dialog and worker
        this->create_async_dialog(tr("Certificate Request Generation"));
        // create connections and start thread
        QObject::connect(this->SSLthread, SIGNAL(started()),     this->sslworker, SLOT(create_csr_and_key()));
        QObject::connect(this->SSLthread, SIGNAL(finished()),    this, SLOT(DlgGenerateCSRFinished()));
        SSLthread->start();

        emit add_text_output(tr("Generating Certificate request and key...\n"));

        break;
    case 1: // Autosign+key
        // Set Key params
        if (this->get_key_param()!=0)
        {
            QMessageBox::warning(this,tr("Error"),tr("Error in Key Param"));
            delete this->Cert;
            return;
        }
        // Ask for serial
        serial=QInputDialog::getText(this, tr("Serial"),
                                       tr("Serial number for cert (decimal):"), QLineEdit::Normal,
                                       QString::number(rand()%100+1), &ok);
        if (serial.isEmpty() || !ok)
        {
            delete this->Cert;
            return;
        }
        serialnum=serial.toUInt(&ok,10);
        if (!ok)
        {
            QMessageBox::warning(this,tr("Error"),tr("Invalid serial"));
            delete this->Cert;
            return;
        }
        this->Cert->set_X509_serial(serialnum);
        // Set start & end date
        if (this->ui->lineEditCertDays->isEnabled())
        {   // Line is enabled, take number of days.
            this->CertStartDate = QDateTime::currentDateTimeUtc();
            serialnum=this->ui->lineEditCertDays->text().toUInt(&ok,10);
            if (!ok)
            {
                QMessageBox::warning(this,tr("Error"),tr("Invalid number of days"));
                delete this->Cert;
                return;
            }
            this->CertEndDate=this->CertStartDate.addDays(serialnum);
        }
        if (this->Cert->set_X509_validity(
                    this->CertStartDate.toString("yyyyMMddHHmmssZ").toLocal8Bit().data(),
                    this->CertEndDate.toString("yyyyMMddHHmmssZ").toLocal8Bit().data())!=0)
        {
            QMessageBox::warning(this,tr("Error"),tr("Invalid start/end"));
            delete this->Cert;
            return;
        }
        // Create async dialog and worker
        this->create_async_dialog(tr("Certificate Generation"));

        // create connections and start thread
        QObject::connect(this->SSLthread, SIGNAL(started()),     this->sslworker, SLOT(create_cert_and_key()));
        QObject::connect(this->SSLthread, SIGNAL(finished()),    this, SLOT(DlgGenerateCertFinished()));
        SSLthread->start();

        emit add_text_output(tr("Generating Certificate and key...\n"));
        break;
    case 2: // CSR (existing key)
        // read key from text input
        switch (this->read_pem_to_openssl())
        {
        case 1: {
            this->display_ssl_err(tr("Error parsing private key"));
            delete this->Cert;
            return;
        }
        case 2: // blame user for forgetting the password :-)
            this->display_ssl_err(tr("Wrong password"));
            delete this->Cert;
            return;
        }
        // Create async dialog and worker
        this->create_async_dialog(tr("CSR from key generation"));

        // create connections and start thread
        QObject::connect(this->SSLthread, SIGNAL(started()),     this->sslworker, SLOT(create_csr_from_key()));
        QObject::connect(this->SSLthread, SIGNAL(finished()),    this, SLOT(DlgGenerateCSRFinished()));
        SSLthread->start();

        emit add_text_output(tr("Generating CSR from existing key...\n"));
        break;
    }
    return;
}

void SSLMainWindow::on_pushButtonDisplayCert_clicked()
{
    // Disable button
    this->ui->pushButtonDisplayCert->setEnabled(false);
    // Create cert object
    this->init_cert();
    // Empty buffer
    this->buffer[0]='\0';
    // Do the display
    this->DisplayCert();
    // Cleanup
    delete this->Cert;
    this->ui->pushButtonDisplayCert->setEnabled(true);
}

void SSLWorker::create_cert_and_key()
{
    int retcode=this->Cert->create_key();
    switch (retcode)
    {
    case 0: // OK
        retcode=this->Cert->create_cert();
        if (retcode==1)
        {
           emit error("Error creating certificate");
        }
        break;
    case 1:
        emit error("Error creating rsa key");
        break;
    case 2:
        emit error("Memory error creating rsa key");
        break;
    case 3:
        emit error("Error calculating rsa key");
        break;
    default:
        emit error("Unknown error, blame dev");
        break;
    }

    emit finished();
}

void SSLWorker::create_csr_and_key()
{
    int retcode=this->Cert->create_key();
    switch (retcode)
    {
    case 0: // OK
        retcode=this->Cert->create_csr();
        if (retcode==1)
        {
           emit error("Error creating csr");
        }
        break;
    case 1:
        emit error("Error creating rsa key");
        break;
    case 2:
        emit error("Memory error creating rsa key");
        break;
    case 3:
        emit error("Error calculating rsa key");
        break;
    default:
        emit error("Unknown error, blame dev");
        break;
    }

    emit finished();
}

void SSLWorker::create_csr_from_key()
{
    int retcode=this->Cert->create_csr();
    if (retcode==1)
    {
       emit error("Error creating csr");
    }
    emit finished();
}

void SSLMainWindow::on_pushButtonTestKey_2_clicked()
{
    // Init cert class
    this->init_cert();
    // Load Certificate
    if (this->read_cert_pem_to_openssl()!=0)
    {
        this->display_ssl_err(tr("Error parsing certificate"));
        return;
    }
    // Load Key
    // Empty buffer
    this->buffer[0]='\0';
    // Read key for GUI to openssl structure
    switch (this->read_pem_to_openssl())
    {
      case 1: {
          this->display_ssl_err(tr("Error parsing private key"));
          delete this->Cert;
          return;
      }
      case 2: //password error
          this->display_ssl_err(tr("Error in password"));
          delete this->Cert;
          return;
    }
    if (this->Cert->check_key()!=0)
    {
        this->display_ssl_err(tr("Invalid Key"));
        delete this->Cert;
        return;
    }
    if (this->ui->radioButtonDisplayCSR->isChecked())
    {
      if (this->Cert->check_key_csr_match() !=0)
      {
          this->display_ssl_err(tr("No match between CSR and key"));
          delete this->Cert;
          return;
      }
      QMessageBox::information(this,tr("Valid"),tr("CSR and key match"));
    }
    else
    {
      if (this->Cert->check_key_cert_match() !=0)
      {
          this->display_ssl_err(tr("No match between cert and key"));
          delete this->Cert;
          return;
      }
      QMessageBox::information(this,tr("Valid"),tr("Certificate and key match"));
    }
    delete this->Cert;
}

/*********** Callbacks **********/

void SSLMainWindow::DlgCertDateAccept(QDateTime startDate,QDateTime endDate)
{
    //accepted()
    this->CertStartDate=startDate;
    this->CertEndDate=endDate;
    this->ui->lineEditCertDays->setText(QString::number(startDate.daysTo(endDate)));
}

void SSLMainWindow::DlgGenerateCSRFinished()
{
    int retcode;
    QString error;
    this->flush_async_dialog();

    if ((this->Cert->SSLError !=0)||(SSLCertificates::abortnow == 1)) // In case of generate error / cancel, just close
    {

    }
    if ((retcode=this->display_generated_key(&error)) != 0)
    {
        if (retcode == 2) this->display_ssl_err(error);
        emit add_text_output(error);
        delete this->Cert;
        this->close_async_dialog();
        return;
    }
    switch (this->Cert->get_csr_PEM(this->buffer,MAX_CERT_SIZE))
    {
    case 0: // no error
        this->ui->textEditCert->setText(this->buffer);
        this->ui->radioButtonDisplayCSR->setChecked(true);
        switch (this->Cert->get_csr_HUM(this->buffer,MAX_CERT_SIZE))
        {
        case 0: // no error
            emit add_text_output(this->buffer);
            break;
        case 1:
            emit add_text_output(tr("Copy error in SSL (csr)"));
            break;
        case 2:
            emit add_text_output(tr("Buffer too small (blame dev)"));
            break;
        case 3:
            emit add_text_output(tr("SSL Error writing csr to PEM"));
            this->display_ssl_err(tr("SSL Error writing csr to PEM"));
            break;
        }
        break;
    case 1:
        emit add_text_output(tr("Certificate : Memory copy error in SSL"));
        break;
    case 2:
        emit add_text_output(tr("Certificate : Buffer too small (blame dev)"));
        break;
    case 3:
        emit add_text_output(tr("Certificate : SSL Error writing PEM"));
        this->display_ssl_err(tr("Certificate : SSL Error writing PEM"));
        break;
    }
    this->display_key_type();
    delete this->Cert;
    this->close_async_dialog();
}

void SSLMainWindow::DlgGenerateCertFinished()
{
    int retcode;
    QString error;
    this->flush_async_dialog();

    if ((this->Cert->SSLError ==1)||(SSLCertificates::abortnow == 1)) // In case of generate error / cancel, just close
    {
        delete this->Cert;
        this->close_async_dialog();
        return;
    }
    if ((retcode=this->display_generated_key(&error)) != 0)
    {
        if (retcode == 2) this->display_ssl_err(error);
        emit add_text_output(error);
        delete this->Cert;
        this->close_async_dialog();
        return;
    }
    switch (this->Cert->get_cert_PEM(this->buffer,MAX_CERT_SIZE))
    {
    case 0: // no error
        ui->textEditCert->setText(this->buffer);
        this->ui->radioButtonDisplayCertificate->setChecked(true);
        switch (this->Cert->get_key_PEM(this->buffer,MAX_CERT_SIZE))
        {
        case 0: // no error
            ui->textEditKey->setText(this->buffer);
            switch (this->Cert->get_cert_HUM(this->buffer,MAX_CERT_SIZE))
                {
                case 0: // no error
                    emit add_text_output(this->buffer);
                    break;
                case 1:
                    emit add_text_output(tr("Copy error in SSL (certificate)"));
                    break;
                case 2:
                    emit add_text_output(tr("Buffer too small (blame dev)"));
                    break;
                case 3:
                    emit add_text_output(tr("SSL Error displaying cert"));
                    this->display_ssl_err(tr("SSL Error displaying cert"));
                    break;
                }
            break;
        case 1:
            emit add_text_output(tr("Memory copy error in SSL"));
            break;
        case 2:
            emit add_text_output(tr("Buffer too small (blame dev)"));
            break;
        case 3:
            emit add_text_output(tr("SSL Error writing PEM"));
            this->display_ssl_err(tr("SSL Error writing PEM"));
            break;
        }
        break;
    case 1:
        emit add_text_output(tr("Certificate : Memory copy error in SSL"));
        break;
    case 2:
        emit add_text_output(tr("Certificate : Buffer too small (blame dev)"));
        break;
    case 3:
        emit add_text_output(tr("Certificate : SSL Error getting cert PEM"));
        this->display_ssl_err(tr("Certificate : SSL Error getting cert PEM"));
        break;
    }

    this->display_key_type();
    delete this->Cert;
    this->close_async_dialog();
}

/*************************** X509 Extensions buttons and utilities *************************/

void SSLMainWindow::add_extension(QString ext, QString value, bool critical)
{
    extensionElmt *newElement =this->addExtensionElmt(ext,0,critical,value);

    addExtensionLine(newElement);
}

void SSLMainWindow::delete_extension(int index)
{
    int i,row=-1;
    for (i=0;i<this->extensionList.count();i++)
    {
        if (this->extensionList.at(i)->index==index)
        {
            extensionElmt *elmt=this->extensionList.at(i);
            row=elmt->row;
            this->ui->TWExtensions->removeRow(row);
            this->extensionList.removeAt(i);
            delete elmt->critical;
            delete elmt->labelWidget;
            delete elmt->deleteBtn;
            // delete elmt->deleteBtnwdg; deleted with row
            delete elmt->deleteBtnwdglayout;
            // delete elmt->criticalwdg; deleted with row
            delete elmt->criticallayout ;
            delete elmt->value;
            delete elmt;
            break;
        }
    }
    if (row==-1)
    {
        QMessageBox::warning(this,tr("Error"),tr("Unknown line to delete"));
        return;
    }
    for (i=0;i<this->extensionList.count();i++)
            if (this->extensionList.at(i)->row > row)
                this->extensionList.at(i)->row--;
}

void SSLMainWindow::extension_button_del_on_clicked(int index)
{
    this->delete_extension(index);
}

void SSLMainWindow::on_pushButtonAddExtension_clicked()
{
    DialogX509v3Extention *Dlg=new DialogX509v3Extention(this);
    QObject::connect(Dlg, SIGNAL(add_extension(QString,QString,bool)),
                     this, SLOT(add_extension(QString,QString,bool)));

    Dlg->exec();
}

/**********************    Key buttons and utilities   *****************************/
/********** GUi events ************/
void SSLMainWindow::on_pushButtonTestKey_clicked()
{
    // Create cert object
    this->init_cert();
    // Empty buffer
    this->buffer[0]='\0';
    // Read key for GUI to openssl structure
    switch (this->read_pem_to_openssl())
    {
    case 1: {
        this->display_ssl_err(tr("Error parsing private key"));
        delete this->Cert;
        return;
    }
    case 2: //password error
        this->display_ssl_err(tr("Error in password"));
        delete this->Cert;
        return;
    }
    if (this->Cert->check_key()!=0)
        this->display_ssl_err(tr("Invalid Key"));
    else
        QMessageBox::information(this,tr("Valid"),tr("Key is valid"));
    delete this->Cert;
}

void SSLMainWindow::on_comboBoxKeyType_currentIndexChanged(const QString &arg1)
{
    //QString keytype=this->ui->comboBoxKeyType->currentText();
    if ((arg1=="rsa")|| arg1=="dsa")
    {
        ui->comboBoxKeySize->clear();
        ui->comboBoxKeySize->addItem("1024",1024);
        ui->comboBoxKeySize->addItem("2048",2048);
        ui->comboBoxKeySize->addItem("4096",4096);
        ui->comboBoxKeySize->addItem("8192",8192);
    }
    if (arg1=="ec")
    {
        this->init_cert();
        ui->comboBoxKeySize->clear();
        for (int i=0;i< this->Cert->keyECListNum;i++)
            ui->comboBoxKeySize->addItem(this->Cert->keyECList[i],
                                         this->Cert->keyECListNIDCode[i]);
    }
}

void SSLMainWindow::on_pushButtonDecryptKey_clicked()
{
    // Disable button
    this->ui->pushButtonDecryptKey->setEnabled(false);
    // Create cert object
    this->init_cert();
    // Empty buffer
    this->buffer[0]='\0';
    // Do the display
    this->DecryptKey();
    // Cleanup
    delete this->Cert;
    this->ui->pushButtonDecryptKey->setEnabled(true);
}

void SSLMainWindow::on_pushButtonEncryptKey_clicked()
{
    // Disable button
    this->ui->pushButtonEncryptKey->setEnabled(false);
    // Create cert object
    this->init_cert();
    // Empty buffer
    this->buffer[0]='\0';
    // Do the display
    this->EncryptKey();
    // Cleanup
    delete this->Cert;
    this->ui->pushButtonEncryptKey->setEnabled(true);
}

void SSLMainWindow::on_pushButtonDisplayKey_clicked()
{
    // Disable button
    this->ui->pushButtonDisplayKey->setEnabled(false);
    // Create cert object
    this->init_cert();
    // Empty buffer
    this->buffer[0]='\0';
    // Do the display
    this->DisplayKey();
    // Cleanup
    delete this->Cert;
    this->ui->pushButtonDisplayKey->setEnabled(true);
}

void SSLMainWindow::on_checkBoxKeyPassEnable_stateChanged(int arg1)
{
    if (arg1==2) {
        ui->lineEditKeyPass->setEnabled(true);
    } else {
        ui->lineEditKeyPass->setEnabled(false);
    }
}

void SSLMainWindow::on_pushButtonGenerate_clicked()
{
    /* First create cert object */
    this->init_cert();

    // Set Key params
    if (this->get_key_param()!=0)
    {
        QMessageBox::warning(this,tr("Error"),tr("Error in Key Param"));
        delete this->Cert;
        return;
    }

    // Create async dialog and worker
    this->create_async_dialog("Key Generation");

    // create connections and start thread
    QObject::connect(this->SSLthread, SIGNAL(started()),     this->sslworker, SLOT(createkey()));
    QObject::connect(this->SSLthread, SIGNAL(finished()),    this, SLOT(DlgGenerateKeyFinished()));
    SSLthread->start();

    emit add_text_output("Generating key...\n");
    return;
}

/********** utilities ************/

int SSLMainWindow::read_pem_to_openssl()
{
    int retcode;
    bool ok;
    QString password;
    // Read content of textEditKey and put it in a Qchar* array
    QByteArray QBskey=this->ui->textEditKey->toPlainText().toLocal8Bit();

    retcode=this->Cert->set_key_PEM(QBskey.data(),nullptr);
    switch (retcode)
    {
    case 0://OK
        break;
    case 1:
    case 3:
        return retcode;
        break;
    case 2:
        ok=true;

        password=QInputDialog::getText(this, tr("Password needed to decrypt key"),
                                           tr("Password to decrypt:"), QLineEdit::Password,
                                           "", &ok);
        if (!password.isEmpty() && ok)
        {
            if (password.toLatin1().size() > PASSWORD_MAX_LENGTH) exit (2);
            retcode=this->Cert->set_key_PEM(QBskey.data(),password.toLocal8Bit().data());
        }
        password="00000000000000"; // TODO check if really overwrites in mem.
        if (retcode==3) // Unknown key type
            return 3;
        if (retcode!=0)// User cancel / empty pass / wrong pass
            return 1;
        break;
    default: // Bad dev documentation !
        //TODO : output debug messsage
        return 1;
        break;
    }
    this->display_key_type();
    return 0;
}

int SSLMainWindow::get_key_param()
{
    unsigned int keysize, keytypeN;
    QString keytype,keyparam;

    keytype=this->ui->comboBoxKeyType->currentText();
    if (keytype=="rsa")
    {
        keytypeN=KeyRSA;
        if ((keysize=this->ui->comboBoxKeySize->currentText().toInt())==0)
            return 1;
        return this->Cert->set_key_params(keysize,keytypeN);
    }
    if (keytype=="dsa")
    {
        keytypeN=KeyDSA;
        if ((keysize=this->ui->comboBoxKeySize->currentText().toInt())==0)
            return 1;
        return this->Cert->set_key_params(keysize,keytypeN);
    }
    if (keytype=="ec")
    {
        keytypeN=KeyEC;
        keyparam=this->ui->comboBoxKeySize->currentText();
        return this->Cert->set_key_params(0,keytypeN,keyparam.toLocal8Bit().data());
    }
    return 1;
}

int SSLMainWindow::display_generated_key(QString* errordisplay)
{
    int retcode;
    if (this->ui->checkBoxKeyPassEnable->isChecked())
    {
        QString keypassword=this->ui->lineEditKeyPass->text();
        QString cipheralg=this->ui->comboBoxKeyCipher->currentText();
        if (keypassword== "")
        {
            *errordisplay=tr("Password is empty");
            return 1;
        }
        if (this->Cert->set_cipher(cipheralg.toLatin1().data()) !=0)
        {
            *errordisplay=tr("Cipher unknown");
            return 2;
        }
        if ((retcode = this->Cert->get_key_PEM_enc(this->buffer,MAX_CERT_SIZE,keypassword.toLatin1().data()))!=0)
        {
            switch (retcode)
            {
            case 1:
                *errordisplay=tr("Memory copy error in SSL");
                return 1;
            case 2:
                *errordisplay=tr("Buffer too small (blame dev)");
                return 1;
            case 3:
                *errordisplay=tr("SSL Error writing PEM");
                return 2;
            default:
                *errordisplay=tr("Unhandled Errror");
                return 2;
            }
        }
    }
    else
    {
        if ((retcode = this->Cert->get_key_PEM(this->buffer,MAX_CERT_SIZE))!=0)
        {
            switch (retcode)
            {
            case 1:
                *errordisplay=tr("Memory copy error in SSL");
                return 1;
            case 2:
                *errordisplay=tr("Buffer too small (blame dev)");
                return 1;
            case 3:
                *errordisplay=tr("SSL Error writing PEM");
                return 2;
            default:
                *errordisplay=tr("Unhandled Errror");
                return 2;
            }
        }
    }

    ui->textEditKey->setText(this->buffer);
    return 0;
}

void SSLMainWindow::display_key_type()
{
    char keytype[20];
    this->Cert->get_key_type(keytype);
    QString keytypeoutput="Type : ";
    keytypeoutput += keytype;
    this->ui->labelDisplayKeyType->setText(keytypeoutput);
}

void SSLWorker::createkey()
{
    int retcode=this->Cert->create_key();
    switch (retcode)
    {
    case 0: // OK
        break;
    case 1:
        emit error("Error creating rsa key");
        break;
    case 2:
        emit error("Memory error creating rsa key");
        break;
    case 3:
        emit error("Error calculating rsa key");
        break;
    default:
        emit error("Unknown error, blame dev");
        break;
    }

    emit finished();
}

void SSLMainWindow::DisplayKey()
{
    // Read key for GUI to openssl structure
    switch (this->read_pem_to_openssl())
    {
    case 1: {
        this->display_ssl_err(tr("Error parsing private key"));
        return;
    }
    case 2: // blame user for forgetting the password :-)
        this->display_ssl_err(tr("Wrong password"));
        return;
    }

    // Read key from openssl strcture to human readable format.
    switch (this->Cert->get_key_HUM(this->buffer,MAX_CERT_SIZE))
    {
    case 1:
        this->display_ssl_err(tr("Copy error in SSL"));
        return;
    case 2:
        this->display_ssl_err(tr("Buffer too small (blame dev)"));
        return;
    case 3:
        this->display_ssl_err(tr("SSL Error writing PEM"));
        return;
    }

    // Show key (use error dialog...)
    DialogSSLErrors * ErrDlg=new DialogSSLErrors (tr("Key Display"),this->buffer,this);
    ErrDlg->setWindowTitle(tr("Display"));
    ErrDlg->setModal(true);
    ErrDlg->exec();
    // cleanup
    delete ErrDlg;
    return;
}

void SSLMainWindow::EncryptKey()
{
    // Read key for GUI to openssl structure
    switch (this->read_pem_to_openssl())
    {
    case 1: {
        this->display_ssl_err(tr("Error parsing private key"));
        return;
    }
    case 2: //maybe blame user another time for forgetting the password ?
        this->display_ssl_err(tr("Error parsing private key"));
        return;
    }
    // Get the Cipher algo to use and put it in openssl.
    QString cipheralg=this->ui->comboBoxKeyCipher->currentText();
    if (this->Cert->set_cipher(cipheralg.toLatin1().data()) !=0)
    {
        this->display_ssl_err(tr("Cipher unknown"));
        return;
    }

    // Ask for the new password
    bool ok=true;
    QString password;
    password=QInputDialog::getText(this, tr("Password to encrypt key"),
                                   tr("Password to encrypt:"), QLineEdit::Password,
                                   "", &ok);
    if (password.isEmpty() || !ok) // If user clicks cancel or empty password
    {
        return;
    }
    if (password.toLatin1().size() > PASSWORD_MAX_LENGTH) exit (2); // Stupidity is punished :-)

    // get the encrypted form of the key
    if (this->Cert->get_key_PEM_enc((char*)this->buffer,MAX_CERT_SIZE,password.toLatin1().data()) != 0)
    {
        password="00000000000000";
        this->display_ssl_err(tr("Error encrypt private key"));
        return;
    }
    ui->textEditKey->setText(this->buffer);
    // cleanup
    password="00000000000000";
}

void SSLMainWindow::DecryptKey()
{
    switch (this->read_pem_to_openssl())
    {
    case 1: {
        this->display_ssl_err(tr("Error parsing private key"));
        return;
    }
    case 2: //maybe blame user another time for forgetting the password ?
        this->display_ssl_err(tr("Error parsing private key"));
        return;
    }
    switch (this->Cert->get_key_PEM(this->buffer,MAX_CERT_SIZE))
    {
    case 0: // no error
        ui->textEditKey->setText(this->buffer);
        break;
    case 1:
        QMessageBox::warning(this,tr("Error"),tr("Copy error in SSL"));
        break;
    case 2:
        QMessageBox::warning(this,tr("Error"),tr("Buffer too small (blame dev)"));
        break;
    case 3:
        this->display_ssl_err(tr("SSL Error writing PEM"));
        break;
    }
}

/*********** Callbacks **********/

void SSLMainWindow::DlgGenerateKeyFinished()
{
    int retcode;
    QString error;
    this->flush_async_dialog();
    if ((this->Cert->SSLError !=0)||(SSLCertificates::abortnow != 0)) // In case of generate error / cancel, just close
    {
        delete this->Cert;
        this->close_async_dialog();
        return;
    }

    if ((retcode=this->display_generated_key(&error)) != 0)
    {
        if (retcode == 2) this->display_ssl_err(error);
        emit add_text_output(error);
        delete this->Cert;
        this->close_async_dialog();
        return;
    }

    switch (this->Cert->get_key_HUM(this->buffer,MAX_CERT_SIZE))
    {
    case 0: // no error
        emit add_text_output(this->buffer);
        break;
    case 1:
        emit add_text_output(tr("Copy error in SSL"));
        break;
    case 2:
        emit add_text_output(tr("Buffer too small (blame dev)"));
        break;
    case 3:
        emit add_text_output(tr("SSL Error writing PEM"));
        this->display_ssl_err(tr("SSL Error writing PEM"));
        break;
    default:
        emit add_text_output(tr("Unhandled Errror"));
        this->display_ssl_err(tr("Unhandled Errror"));
    }
    this->display_key_type();

    delete this->Cert;
    this->close_async_dialog();
}

void SSLMainWindow::DlgGenerateKeyError(QString strError)
{
    // Abort will generate errors, but it's useless to display them
    if (SSLCertificates::abortnow == 1) return;
    this->display_ssl_err(tr("Error : ") + strError);
}

void SSLMainWindow::DlgGenerateKeyAbort()
{
    SSLCertificates::abortnow = 1;
}

/**********************   Load, save, export functions *****************************/
void SSLMainWindow::on_pushButtonSaveKey_clicked()
{
    QString filename=QFileDialog::getSaveFileName(this, "Save key", "",
                       tr("Key (*.pem *.key);;Any (*.*)"));
    if (filename=="") return;
    QFile file( filename );
    if (! file.open( QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(this,tr("Error"),tr("Cannot write to file"));
        return;
    }
    QTextStream out(&file);
    out << this->ui->textEditKey->toPlainText();
    file.close();
    QMessageBox::information(this,tr("Saved"),tr("Key saved"));
}

void SSLMainWindow::on_pushButtonLoadKey_clicked()
{
    QString key;
    QString filename=QFileDialog::getOpenFileName(this, "Load key", "",
                       tr("Key (*.pem *.key);;Any (*.*)"));
    if (filename=="") return;
    QFile file( filename );
    if (! file.open( QIODevice::ReadOnly | QIODevice::Text))
    {
        QMessageBox::warning(this,tr("Error"),tr("Cannot read file"));
        return;
    }
    QTextStream out(&file);
    key = out.readAll();
    file.close();
    this->ui->textEditKey->setText(key);

    // Create cert object
    this->init_cert();
    // Empty buffer
    this->buffer[0]='\0';
    // Read key for GUI to openssl structure
    switch (this->read_pem_to_openssl())
    {
    case 1: {
        this->display_ssl_err(tr("Error parsing private key"));
        delete this->Cert;
        return;
    }
    case 2: //password error
        this->display_ssl_err(tr("Error in password"));
        delete this->Cert;
        return;
    }
    if (this->Cert->check_key()!=0)
        this->display_ssl_err(tr("Invalid Key"));
    else
    {
        switch (this->Cert->get_key_type())
        {
        case KeyRSA:
            this->ui->labelKeyType->setText("rsa");
            break;
        case KeyDSA:
            this->ui->labelKeyType->setText("dsa");
            break;
        case KeyEC:
            this->ui->labelKeyType->setText("ec");
            break;
        default:
            this->ui->labelKeyType->setText("unknown");
        }
    }
    QMessageBox::information(this,tr("Valid"),tr("Valid key, type ")+this->ui->labelKeyType->text());
    delete this->Cert;
}

void SSLMainWindow::on_pushButtonSaveCert_clicked()
{
    QString filename=QFileDialog::getSaveFileName(this, "Save certificate", "",
                       tr("Cert (*.crt *.pem *.cer *.csr);;Any (*.*)"));
    if (filename=="") return;
    QFile file( filename );
    if (! file.open( QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(this,tr("Error"),tr("Cannot write to file"));
        return;
    }
    QTextStream out(&file);
    out << this->ui->textEditCert->toPlainText();
    file.close();
    QMessageBox::information(this,tr("Saved"),tr("Certificate saved"));
}

void SSLMainWindow::on_pushButtonLoadCert_clicked()
{
    QString cert;
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
    cert = out.readAll();
    file.close();
    this->ui->textEditCert->setText(cert);

    // TODO : check cert by loading it
    // TODO : set cert/csr radio buttons

}

void SSLMainWindow::on_pushButtonSave2p12_clicked() // TODO : finish this
{
    // Init cert class
    this->init_cert();
    // read key
    switch (this->read_pem_to_openssl())
    {
    case 1: {
        this->display_ssl_err(tr("Error parsing private key"));
        delete this->Cert;
        return;
    }
    case 2: //password error
        this->display_ssl_err(tr("Error in password"));
        delete this->Cert;
        return;
    }
    // read cert
    switch (this->read_cert_pem_to_openssl())
    {
    case 1: {
        this->display_ssl_err(tr("Error parsing certificate"));
        delete this->Cert;
        return;
    }
    case 2: //maybe blame user another time for forgetting the password ?
        this->display_ssl_err(tr("Error parsing certificate"));
        delete this->Cert;
        return;
    }

    //QMessageBox::information(this,"Name",this->Cert->get_pkcs12_name());
    dlgP12 = new CDialogPKCS12 (this->Cert,"",true,this);

    QObject::connect(dlgP12, SIGNAL(DlgPKCS12_Finished(bool,bool,int)),
                     this, SLOT(DlgPKCS12_Finished(bool,bool,int )));

    dlgP12->show();

    return;



}

void SSLMainWindow::on_pushButtonLoadPKCS12_clicked()
{
    int retcode;
    // Init cert class
    this->init_cert();

    // Get filename
    QString filename=QFileDialog::getOpenFileName(this, "Load pkcs12", "",
                       tr("pkcs12 (*.p12 *.pfx);;Any (*.*)"));
    if (filename=="")
    {
        delete this->Cert;
        return;
    }
    FILE* file;
    file=fopen(filename.toLocal8Bit().data(),"rb");

    if ((retcode=this->Cert->load_pkcs12(file,"")) != 0) // TODO : check what precise error generates pass failure
    {
        rewind(file);
        bool ok=true;
        QString password;
        password=QInputDialog::getText(this, tr("Password for ")+filename,
                                           tr("Password :"), QLineEdit::Password,
                                           "", &ok);
        if (!password.isEmpty() && ok)
        {
            if (password.toLatin1().size() > PASSWORD_MAX_LENGTH) exit (2);

            retcode=this->Cert->load_pkcs12(file,password.toLatin1().data());
        }
        password="00000000000000";

        if (retcode != 0)
        {
          switch (retcode)
          {
            case 1: this->display_ssl_err(tr("Error loading p12 file"));
              break;
            case 2: this->display_ssl_err(tr("Error parsing p12 file"));
              break;
            case 3: this->display_ssl_err(tr("Unsupported key type"));
              break;
          }
          delete this->Cert;
          fclose(file);
          return;
         }
    }

    fclose(file);

    //QMessageBox::information(this,"Name",this->Cert->get_pkcs12_name());
    dlgP12 = new CDialogPKCS12 (this->Cert,filename,false,this);

    QObject::connect(dlgP12, SIGNAL(DlgPKCS12_Finished(bool,bool,int)),
                     this, SLOT(DlgPKCS12_Finished(bool,bool,int )));

    dlgP12->show();

    return;

}

void SSLMainWindow::DlgPKCS12_Finished(bool Cancel, bool MainCertImport, int caCertImport)
{
  int retcode;
  if ( ! Cancel)
  {
    if (MainCertImport)
    {
      /** Get Certificate */
      if ((retcode=this->Cert->get_cert_PEM(this->buffer,MAX_CERT_SIZE)) != 0)
      {
         switch(retcode)
         {
            case 1: this->display_ssl_err(tr("Certificate : Memory copy error in SSL"));
             break;
            case 2: this->display_ssl_err(tr("Buffer too small (blame dev)"));
             break;
            case 3: this->display_ssl_err(tr("Certificate : SSL Error writing PEM"));
             break;
         }
      }
      else
      {
        ui->textEditCert->setText(this->buffer);
        ui->radioButtonDisplayCertificate->setChecked(true);
        /** Get Key */
        if ((retcode= this->Cert->get_key_PEM(this->buffer,MAX_CERT_SIZE)) != 0)
        {
           switch(retcode)
           {
              case 1: this->display_ssl_err(tr("Key : Memory copy error in SSL"));
               break;
              case 2: this->display_ssl_err(tr("Buffer too small (blame dev)"));
               break;
              case 3: this->display_ssl_err(tr("Key : SSL Error writing PEM"));
               break;
           }
        }
        else
        {
          ui->textEditKey->setText(this->buffer);
        }

      }
    }
    else
    {
      if ((retcode=this->Cert->get_pkcs12_certs_pem(caCertImport,this->buffer,MAX_CERT_SIZE)) != 0)
      {
         switch(retcode)
         {
            case 1: this->display_ssl_err(tr("Certificate : Memory copy error in SSL"));
             break;
            case 2: this->display_ssl_err(tr("Buffer too small (blame dev)"));
             break;
            case 3: this->display_ssl_err(tr("Certificate : SSL Error writing PEM"));
             break;
         }
      }
      else
      {
        ui->textEditCert->setText(this->buffer);
        this->ui->radioButtonDisplayCertificate->setChecked(true);
        ui->textEditKey->setText("");
      }
     }
  }
  delete this->Cert;
  this->dlgP12->close();
  this->dlgP12->deleteLater();
}

/************************ Settings ************************************************/


void SSLMainWindow::get_settings(QString setting)
{
    setting+=".ini";
    QSettings settings(setting, QSettings::IniFormat, this);
    //Cert object
    this->ui->lineEditCertCN->setText(settings.value("Cert/CN","Cert object").toString());
    this->ui->lineEditCertC->setText(settings.value("Cert/C","").toString());
    this->ui->lineEditCertS->setText(settings.value("Cert/S","").toString());
    this->ui->lineEditCertL->setText(settings.value("Cert/L","").toString());
    this->ui->lineEditCertO->setText(settings.value("Cert/O","").toString());
    this->ui->lineEditCertOU->setText(settings.value("Cert/OU","").toString());
    this->ui->lineEditCertEmail->setText(settings.value("Cert/Email","").toString());
    this->ui->lineEditCertDays->setText(settings.value("Cert/ValidDays","365").toString());

    // extensions
    // First reset
    for (int i=0;i<this->extensionList.count();i++)
    {
        emit this->extensionList.at(i)->deleteBtn->click();
    }
    // Then fill up
    int extnum=settings.value("Extension/total_number",0).toInt();
    QString extname="Extension/ext";
    for (int i=0;i<extnum;i++)
    {
        extensionElmt * newelement = this->addExtensionElmt(
                    settings.value(extname+"label"+QString::number(i),"Error").toString(),
                    settings.value(extname+"NID"+QString::number(i),0).toInt(),
                    settings.value(extname+"critical"+QString::number(i),false).toBool(),
                    settings.value(extname+"value"+QString::number(i),"Error").toString());
        addExtensionLine(newelement);
    }

    // Check for updates
    this->checkUpdate=settings.value("Global/checkupdate",3).toInt();
    this->checkUpdateNum=settings.value("Global/checkupdate_num",0).toInt();
}

void SSLMainWindow::save_settings(QString setting)
{
    setting+=".ini";
    QSettings settings(setting, QSettings::IniFormat, this);
    //Cert object
    settings.setValue("Cert/CN",this->ui->lineEditCertCN->text().toLocal8Bit());
    settings.setValue("Cert/C",this->ui->lineEditCertC->text().toLocal8Bit());
    settings.setValue("Cert/S",this->ui->lineEditCertS->text().toLocal8Bit());
    settings.setValue("Cert/L",this->ui->lineEditCertL->text().toLocal8Bit());
    settings.setValue("Cert/O",this->ui->lineEditCertO->text().toLocal8Bit());
    settings.setValue("Cert/OU",this->ui->lineEditCertOU->text().toLocal8Bit());
    settings.setValue("Cert/Email",this->ui->lineEditCertEmail->text().toLocal8Bit());
    settings.setValue("Cert/ValidDays",this->ui->lineEditCertDays->text().toLocal8Bit());

    settings.setValue("Extension/total_number",this->extensionList.count());
    QString extname="Extension/ext";
    for (int i=0;i<this->extensionList.count();i++)
    {
        settings.setValue(extname+"label"+QString::number(i),this->extensionList.at(i)->label.toLocal8Bit());
        settings.setValue(extname+"value"+QString::number(i),this->extensionList.at(i)->value->text().toLocal8Bit());
        settings.setValue(extname+"NID"+QString::number(i),this->extensionList.at(i)->NID);
        settings.setValue(extname+"critical"+QString::number(i),this->extensionList.at(i)->critical->isChecked());
    }
}

void SSLMainWindow::on_pushButtonSaveSettings_clicked()
{
    this->save_settings("default");
}

/************************ Update stuff ********************************************/

void SSLMainWindow::check_updates()
{
    if (this->checkUpdate==0)
        return;
    if (this->checkUpdate==3)
    {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, tr("Check for updates"), tr("Do you want to check for updates at startup ?\nInformation sent is : version + platform"),
                                      QMessageBox::Yes|QMessageBox::No);
        QSettings settings("default.ini", QSettings::IniFormat, this);
        if (reply == QMessageBox::Yes) {
          settings.setValue("Global/checkupdate",1);
          this->checkUpdate=1;
        } else {
          settings.setValue("Global/checkupdate",0);
          this->checkUpdate=0;
          return;
        }
    }
    //qDebug() << QSslSocket::supportsSsl() << endl << QSslSocket::sslLibraryBuildVersionString() <<endl << QSslSocket::sslLibraryVersionString();
    network = new QNetworkAccessManager(this);
    connect(network, SIGNAL(finished(QNetworkReply*)),
            this, SLOT(network_reply_finished(QNetworkReply*)));
    connect(network,SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)),
            this,SLOT(network_reply_SSL_error(QNetworkReply*,QList<QSslError>)));

    QUrl updateurl=QUrl(UPDATESRC);

    QUrlQuery postdata;
    // Why are you looking at this, you didn't trust the message box :-) ?
    postdata.addQueryItem("secret",USER_ALL_PASSWORDS_FOUND);
    postdata.addQueryItem("version",YAOGVERSIONF);
    postdata.addQueryItem("platform",YAOGPLATFORM);

    QNetworkRequest request=QNetworkRequest(updateurl);
    QSslConfiguration sslconf(QSslConfiguration::defaultConfiguration());
    request.setSslConfiguration(sslconf);

   // qDebug() << sslconf.->sslLibraryBuildVersionString()
    //sslSocket->sslLibraryVersionString()

    request.setRawHeader("User-Agent", "YAOG Update 1.0");
    request.setHeader(QNetworkRequest::ContentTypeHeader,"application/x-www-form-urlencoded");

    network->post(request,postdata.toString(QUrl::FullyEncoded).toUtf8());
}

void SSLMainWindow::network_reply_SSL_error(QNetworkReply* reply,QList<QSslError> SSLErr)
{
  qDebug() << "SSL error";
  int size=SSLErr.size();
  while ( size>0)
    {
      qDebug() << SSLErr.at(size).errorString();
      size--;
    }
  reply->deleteLater();
  //TODO : do something.
}

void SSLMainWindow::network_reply_finished(QNetworkReply* reply) //TODO
{
    QRegExp ok("^OK:.*");
    QRegExp update("^UPDATE:.*");
    QByteArray bts = reply->readAll();
    QString str(bts);
    //QMessageBox::information(this,"Reply","return  : "+str,"OK");
    reply->deleteLater();

    if (ok.exactMatch(str))
    {
        //QMessageBox::information(this,"Up to date",str,"OK");
        return;
    }
    if (update.exactMatch(str))
    { // TODO : download and update after user OK with it
      if (this->checkUpdateNum == 0)
      {
        QMessageBox::information(this,"Update Available",str,"OK");
        this->checkUpdateNum = 10;
      }
      else
      {
        this->checkUpdateNum--;
      }
      QSettings settings("default.ini", QSettings::IniFormat, this);
      settings.setValue("Global/checkupdate_num",this->checkUpdateNum);
      return;
    }
    //QMessageBox::information(this,"Error update","returned : " + str);
    //TODO On all other errors, check last OK reply : if older than 1 month, alert user
    //For now, silently die (alone)
}
