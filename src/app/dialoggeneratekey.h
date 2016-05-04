#ifndef DIALOGGENERATEKEY_H
#define DIALOGGENERATEKEY_H

#include <QDialog>
#include "sslcertificates.h"

namespace Ui {
class DialogGenerateKey;
}

class DialogGenerateKey : public QDialog
{
    Q_OBJECT

public:
    explicit DialogGenerateKey(QString title,QWidget *parent = 0);
    ~DialogGenerateKey();

private:
    Ui::DialogGenerateKey *ui;

public slots:
    void add_text_output(QString msg);
    void finished_calc();

signals:
    void btn_abort_pressed();

private slots:
    void on_pushButtonAbort_clicked();
};

#endif // DIALOGGENERATEKEY_H
