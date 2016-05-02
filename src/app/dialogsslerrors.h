#ifndef DIALOGSSLERRORS_H
#define DIALOGSSLERRORS_H

#include <QDialog>

namespace Ui {
class DialogSSLErrors;
}

class DialogSSLErrors : public QDialog
{
    Q_OBJECT

public:
    explicit DialogSSLErrors(QString label, QString errors, QWidget *parent = 0);
    ~DialogSSLErrors();

private:
    Ui::DialogSSLErrors *ui;
};

#endif // DIALOGSSLERRORS_H
