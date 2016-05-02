#include "dialoggeneratekey.h"
#include "ui_dialoggeneratekey.h"

DialogGenerateKey::DialogGenerateKey(QString title="Output", QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogGenerateKey)
{
    ui->setupUi(this);
    this->setWindowTitle(title);
}

DialogGenerateKey::~DialogGenerateKey()
{
    delete ui;
}

void DialogGenerateKey::add_text_output(QString msg)
{
   QString actualMsg=this->ui->labelOutput->toPlainText();
   actualMsg+=msg;
   this->ui->labelOutput->setText(actualMsg);
}
void DialogGenerateKey::finished_calc()
{
    this->ui->pushButtonClose->setEnabled(true);
    this->ui->pushButtonAbort->setEnabled(false);
}

void DialogGenerateKey::on_pushButtonAbort_clicked()
{
    this->ui->pushButtonAbort->setEnabled(false);
    emit btn_abort_pressed();
}
