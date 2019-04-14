#ifndef CDIALOGPKCS12_H
#define CDIALOGPKCS12_H

#include <QDialog>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
//#include "sslmainwindow.h"
#include "sslcertificates.h"
#include "stackwindow.h"

#define MAX_CERT_SIZE 30000

namespace Ui {
  class CDialogPKCS12;
}

class CDialogPKCS12 : public QDialog
{
  Q_OBJECT

public:
  explicit CDialogPKCS12( SSLCertificates * Certificate, QString Filename, bool write, CStackWindow* cur_stack,QWidget *parent = nullptr);
  ~CDialogPKCS12();

private:
  Ui::CDialogPKCS12 *ui;
  SSLCertificates * cert;
  QString file;
  bool isWrite;
  CStackWindow* stack;

signals:
  void DlgPKCS12_Finished(bool Cancel, bool MainCertImport, int caCertImport);

public slots:
  void stack_cert_selected(CStackWindow::CertData certificate);

private slots:
  void on_pushButtonLoadCert_clicked();
  void on_pushButtonImportMain_clicked();
  void on_pushButtonImportCert_clicked();
  void on_pushButtonSaveAs_clicked();
  void on_pushButtonCancel_clicked();
  void on_pushButtonSelectFromStack_clicked();
  void on_pushButtonPushAll_clicked();
};

#endif // CDIALOGPKCS12_H
