#include "dialogx509extensions.h"
#include "ui_dialogx509extensions.h"

DialogX509Extensions::DialogX509Extensions(QWidget *parent) :
  QDialog(parent),
  ui(new Ui::DialogX509Extensions)
{
  ui->setupUi(this);
}

DialogX509Extensions::~DialogX509Extensions()
{
  delete ui;
}
