#ifndef DIALOGX509V3EXTENTION_H
#define DIALOGX509V3EXTENTION_H

#include <QDialog>
#include <QMessageBox>
#include "sslcertificates.h"

namespace Ui {
class DialogX509v3Extention;
}

class DialogX509v3Extention : public QDialog
{
    Q_OBJECT

public:
    explicit DialogX509v3Extention(QWidget *parent = 0);
    ~DialogX509v3Extention();

private:
    SSLCertificates *Cert; //!< Used to get extensions
private slots:
    void on_pushButtonOKExtension_clicked();

    void on_pushButtonAddValue_clicked();

    void on_checkBoxCritical_clicked();

    void on_pushButtonAdd_clicked();

    void on_pushButtonResetForm_clicked();

    void on_buttonBox_accepted();

private:
    Ui::DialogX509v3Extention *ui;
    void reset_form();

signals:
    void add_extension(QString ext, QString value, bool critical);
};

#endif // DIALOGX509V3EXTENTION_H
