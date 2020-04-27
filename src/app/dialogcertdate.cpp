#include "dialogcertdate.h"
#include "ui_dialogcertdate.h"

DialogCertDate::DialogCertDate(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogCertDate)
{
    ui->setupUi(this);
    QDateTime now = QDateTime::currentDateTimeUtc();
    this->ui->dateTimeEditStartDate->setDateTime(now);
    now=now.addDays(365);
    this->ui->dateTimeEditEndValid->setDateTime(now);

}

DialogCertDate::~DialogCertDate()
{
    delete ui;
}

void DialogCertDate::calcDays()
{
    QDateTime start,end;
    start=this->ui->dateTimeEditStartDate->dateTime();
    end=this->ui->dateTimeEditEndValid->dateTime();
    QString duration = "Validity : " + QString::number(start.daysTo(end)) + " days.";
    this->ui->labelDuration->setText(duration);
}

void DialogCertDate::on_buttonBox_accepted()
{
    emit DlgCertDateAccept(this->ui->dateTimeEditStartDate->dateTime() ,
                           this->ui->dateTimeEditEndValid->dateTime());
}

void DialogCertDate::on_dateTimeEditStartDate_dateChanged(const QDate &date)
{
    Q_UNUSED(date);
    this->calcDays();
}

void DialogCertDate::on_dateTimeEditEndValid_dateChanged(const QDate &date)
{
    Q_UNUSED(date);
    this->calcDays();
}
