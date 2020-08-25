#ifndef DIALOGX509EXTENSIONS_H
#define DIALOGX509EXTENSIONS_H

#include <QDialog>

namespace Ui {
class DialogX509Extensions;
}

class DialogX509Extensions : public QDialog
{
  Q_OBJECT

public:
  explicit DialogX509Extensions(QWidget *parent = nullptr);
  ~DialogX509Extensions();

private:
  Ui::DialogX509Extensions *ui;
};

#endif // DIALOGX509EXTENSIONS_H
