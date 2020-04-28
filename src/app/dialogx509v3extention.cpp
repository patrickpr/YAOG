#include "dialogx509v3extention.h"
#include "ui_dialogx509v3extention.h"

DialogX509v3Extention::DialogX509v3Extention(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogX509v3Extention)
{
    ui->setupUi(this);
    try { this->Cert=new SSLCertificates(); }
    catch (int e)
    {
        QMessageBox msgBox;
        if (e==10)  msgBox.setText(tr("Error initializing key(s) : program will end"));
        if (e==20)  msgBox.setText(tr("Error initializing certificate : program will end"));
        msgBox.exec();
        exit(1);
    }
    this->reset_form();
}

DialogX509v3Extention::~DialogX509v3Extention()
{
    delete this->Cert;
    delete ui;
}

void DialogX509v3Extention::on_pushButtonOKExtension_clicked()
{
    QString extName=this->ui->comboBoxNameChooser->currentText();
    QString value;
    QStringList valueList;
    int i,j;

    this->ui->comboBoxNameChooser->setEnabled(false);
    this->ui->pushButtonOKExtension->setEnabled(false);
    this->ui->checkBoxCritical->setEnabled(true);
    this->ui->comboBoxExtensionValue->setEnabled(true);
    this->ui->lineEditValue->setEnabled(true);
    this->ui->pushButtonAddValue->setEnabled(true);

    for (i=0; i<this->Cert->X509ExtensionHelpNum;i++)
    {
        if (extName == QString::fromStdString(this->Cert->X509ExtensionHelp[i].name))
        {
            value=QString::fromStdString(this->Cert->X509ExtensionHelp[i].values);
            valueList=value.split(",");
            for (j=0; j<valueList.count();j++)
            {
                ui->comboBoxExtensionValue->addItem(valueList.at(j),j);
            }
            break;
        }
    }
    extName += "=";
    this->ui->labelExtensionNameOutput->setText(extName);
    this->ui->pushButtonResetForm->setEnabled(true);
    this->ui->pushButtonAdd->setEnabled(true);
}

void DialogX509v3Extention::on_pushButtonAddValue_clicked()
{
    QString value=this->ui->lineEditValue->text();

    if (!value.isEmpty())
        value +=",";
    value+=this->ui->comboBoxExtensionValue->currentText();
    this->ui->lineEditValue->setText(value);
}

void DialogX509v3Extention::on_checkBoxCritical_clicked()
{
    QString label=this->ui->comboBoxNameChooser->currentText();
    label +="=";
    if (this->ui->checkBoxCritical->isChecked())
        label += "critical,";
    this->ui->labelExtensionNameOutput->setText(label);
}

void DialogX509v3Extention::reset_form()
{
    while (this->ui->comboBoxExtensionValue->count() != 0)
        this->ui->comboBoxExtensionValue->removeItem(0);
    while (this->ui->comboBoxNameChooser->count() != 0)
        this->ui->comboBoxNameChooser->removeItem(0);
    for (int i=0; i<this->Cert->X509ExtensionHelpNum;i++)
    {
        ui->comboBoxNameChooser->addItem(QString::fromStdString(this->Cert->X509ExtensionHelp[i].name),i);
    }
    ui->checkBoxCritical->setEnabled(false);
    ui->comboBoxExtensionValue->setEnabled(false);
    ui->lineEditValue->setEnabled(false);
    ui->pushButtonAddValue->setEnabled(false);
    this->ui->comboBoxNameChooser->setEnabled(true);
    this->ui->pushButtonOKExtension->setEnabled(true);
    this->ui->checkBoxCritical->setChecked(false);
    this->ui->lineEditValue->setText("");
    this->ui->pushButtonResetForm->setEnabled(false);
    this->ui->pushButtonAdd->setEnabled(false);
    this->ui->labelExtensionNameOutput->setText(tr("<Select Extension>"));

}

void DialogX509v3Extention::on_pushButtonAdd_clicked()
{
     emit add_extension(
                 this->ui->comboBoxNameChooser->currentText(),
                 this->ui->lineEditValue->text(),
                 this->ui->checkBoxCritical->isChecked());
    this->reset_form();
}

void DialogX509v3Extention::on_pushButtonResetForm_clicked()
{
    this->reset_form();
}

void DialogX509v3Extention::on_buttonBox_accepted()
{
    if (!this->ui->lineEditValue->text().isEmpty())
        emit add_extension(
                this->ui->comboBoxNameChooser->currentText(),
                this->ui->lineEditValue->text(),
                this->ui->checkBoxCritical->isChecked());
}
