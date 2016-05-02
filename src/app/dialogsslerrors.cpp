#include "dialogsslerrors.h"
#include "ui_dialogsslerrors.h"

DialogSSLErrors::DialogSSLErrors(QString label, QString errors, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogSSLErrors)
{
    ui->setupUi(this);
    this->ui->labelError->setText(label);
    this->ui->textEditError->setText(errors);
}

DialogSSLErrors::~DialogSSLErrors()
{
    delete ui;
}
