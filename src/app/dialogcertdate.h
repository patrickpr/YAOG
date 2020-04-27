#ifndef DIALOGCERTDATE_H
#define DIALOGCERTDATE_H

#include <QDialog>
#include <QDateTime>

namespace Ui {
class DialogCertDate;
}

class DialogCertDate : public QDialog
{
    Q_OBJECT

public:
    explicit DialogCertDate(QWidget *parent = nullptr);
    ~DialogCertDate();
private:
    void calcDays();

private slots:
    void on_buttonBox_accepted();

    void on_dateTimeEditStartDate_dateChanged(const QDate &date);

    void on_dateTimeEditEndValid_dateChanged(const QDate &date);

private:
    Ui::DialogCertDate *ui;

signals:
    void DlgCertDateAccept(QDateTime startDate, QDateTime endDate);
};

#endif // DIALOGCERTDATE_H
