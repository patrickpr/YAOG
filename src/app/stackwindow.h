#ifndef STACKWINDOW_H
#define STACKWINDOW_H

#include <QDialog>
#include <QDebug>
#include "sslcertificates.h"

namespace Ui {
  class CStackWindow;
}

class CStackWindow : public QDialog
{
  Q_OBJECT

public:
  explicit CStackWindow(QWidget *parent = nullptr);
  ~CStackWindow();

  enum certType {nocert=-1,certificate=0,csr=1};
  enum keyType { nokey=-1,rsa=KeyRSA, dsa=KeyDSA , ec=KeyEC };
  QString keyName[10];
  struct CertData {
    QString key;        //!< PEM format
    keyType key_type;
    QString key_param;  //!< Size for RSA/DSA, type of EC
    QString certificate;//!< PEM format
    certType cert_type;
    QString name;
  };
  int push_cert(CertData *cert);

  void show();
private slots:
  void on_pushButtonHide_clicked();

  void on_pushButtonPurge_clicked();

  void on_pushButtonDelete_clicked();

  void on_pushButtonPop_clicked();

protected slots:
    void select_cert();

private:
  void stack_empty(bool empty);//!< disable or enable buttons when stack is empty or not
  void update_list();

  QWidget * mainWindow;
  QPoint windowsPosition;
  bool   windowsPositionSet;
  Ui::CStackWindow *ui;

  QList<CertData> stack;

signals:
  void pop_certificate(CStackWindow::CertData certificate);
};

#endif // STACKWINDOW_H
