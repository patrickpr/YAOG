#ifndef SSLMAINWINDOW_H
#define SSLMAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QThread>
#include <QMutex>
#include <QTimer>
#include <QDebug>
#include <QInputDialog>
#include <QSignalMapper>
#include <QFileDialog>
#include <QDateTime>
#include <QLayout>
#include <QSettings>

#include <QtNetwork>
#include "sslcertificates.h"
#include "dialoggeneratekey.h"
#include "dialogsslerrors.h"
#include "dialogcertdate.h"
#include "dialogx509v3extention.h"

#define YAOGVERSION "1.0"
#define YAOGPLATFORM "W32"

#define PASSWORD_MAX_LENGTH 100
#define MAX_CERT_SIZE 30000

#define OUTPUT_TYPE_CERT 1
#define OUTPUT_TYPE_CSR 2

namespace Ui {
class SSLMainWindow;
}

/**
 * @brief The SSLWorker class
 * Used to create key and certificates in a separate thread
 */
class SSLWorker : public QObject {
    Q_OBJECT

public:
    /**
     * @brief SSLWorker constructor
     * @param newcert Existing SSLCertificates class to use
     */
    SSLWorker(SSLCertificates *newcert);
    ~SSLWorker();

public slots:
    /**
     * @brief createkey
     * All parameters must be set before calling this
     */
    void createkey();
    /**
     * @brief create_cert_and_key
     * All parameters must be set before calling this
     */
    void create_cert_and_key();
    /**
     * @brief create_csr_and_key
     * All parameters must be set before calling this
     */
    void create_csr_and_key();

signals:
    /**
     * @brief finished Qt signal emited at end of
     */
    void finished();
    void error(QString err);

private:
    /**
     * @brief Cert Contains class used for threaded calculations
     */
    SSLCertificates* Cert;
};

// TODO : use this as a stack for cert/keys, etc...
typedef struct CertData {
    QString key;
    QString certificate;
    QString CSR;
    QString name;
} CertData;

/**
 * @brief The SSLMainWindow class
 * App Main window
 */
class SSLMainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit SSLMainWindow(QWidget *parent = 0);
    ~SSLMainWindow();
    /**
     * @brief Output buffer of openssl callback
     */
    static QString CBdata;
    /**
     * @brief Mutex for Read/write of CBdata
     */
    static QMutex CBMutex;
    /**
     * @brief Add data to CBdata using CBMutex
     * @param String to add
     */
    static void CB_add_data(char* data);
    /**
     * @brief Read and erase existing string in buffer CBdata
     * @return message from openssl
     */
    static QString CB_read_data();

    // For future use
    QList<struct Certdata *> CertificateList;

    typedef struct extensionElmt {
        QPushButton * deleteBtn;        //!< Display widget
        QWidget* deleteBtnwdg;          //!< Display widget
        QHBoxLayout* deleteBtnwdglayout;    //!< Display widget
        QWidget* criticalwdg;           //!< Display widget
        QHBoxLayout* criticallayout;    //!< Display widget
        QLabel* labelWidget;            //!< Display widget
        QLineEdit* value;               //!< Value of extension
        QCheckBox * critical;           //!< Critical extension if checked
        QString label;                  //!< Name of extension
        unsigned int NID;               //!< NID of extension (not used)
        int row;                        //!< Actual row in QTableWidget
        int index;                      //!< Index for signal mapping
    } extensionElmt; //!< Structure for X509 extension
    QList<extensionElmt *> extensionList; //!<List of X509 extensions
    int extensionElmtMapIndex; //!< Mapping index for signal from checkbox of extensionElmt
    /**
     * @brief addExtensionElmt adds an element in QList extensionList
     * @param label : label of extension
     * @param NID : NID of extension (if not known -> 0)
     * @param critical : extension is critical
     * @param value : of extension
     * @return Thew new extension or NULL on error
     */
    extensionElmt *addExtensionElmt(QString label, unsigned int NID, bool critical, QString value);
    /**
     * @brief delete_extension and errase is from the widget table
     * @param value of index of extension element as this is called throught a signal mapping
     */
    void delete_extension(int index);
    /**
     * @brief addExtensionLine : adds extension in the wdget table
     * @param elmt to add
     */
    void addExtensionLine(extensionElmt* elmt);

private:
    Ui::SSLMainWindow *ui;

    // Certificate stuff
    SSLCertificates *Cert;
    void init_cert(); //!< creates a new cert and catches errors.
    int cert_output_type; //!< PEM in textDisplay is cert/csr...
    QDateTime CertStartDate; //!< Certificate start date
    QDateTime CertEndDate; //!< Certificate end date

    // Key and cert generation thread and display
    DialogGenerateKey* DlgGenerateKey;
    QThread* SSLthread;
    SSLWorker* sslworker;
    void create_async_dialog(QString title);
    void flush_async_dialog();
    void close_async_dialog();
    QTimer *timer; //!< used to read data in static function

    /**
     * @brief read_pem_to_openssl reads the key in window and puts it in openssl structure
     * Cert must be allocated
     * asks password if needed.
     * @return 0: success , 1: ssl error, 2: password error, 3: unknown key
     */
    int read_pem_to_openssl();
    /**
     * @brief read_cert_pem_to_openssl reads the cert in window and puts it in openssl structure
     * Cert must be allocated
     * asks password if needed.
     * @return 0: success , 1: ssl error, 2: password error
     */
    int read_cert_pem_to_openssl();
    /**
     * @brief display_ssl_err : display ssl errors in new windows
     * @param message : additionnal message to display
     */
    void display_ssl_err(QString message);
    char buffer[MAX_CERT_SIZE]; //!< buffer for openssl BIO
    /**
     * @brief DisplayKey : display key in new windows
     */
    void DisplayKey();
    /**
     * @brief EncryptKey :encrypt key, ask password to encrypt (and if necessary to decrypt)
     */
    void EncryptKey();
    /**
     * @brief DecryptKey : decrypt key
     */
    void DecryptKey();
    /**
     * @brief DisplayCert in new window
     */
    void DisplayCert();
    /**
     * @brief display_key_type in current Cert structure on labelDisplayKeyType.
     */
    void display_key_type();
    /**
     * @brief get_key_param : get key type and param (size, etc...) and put it in this->cert param
     * @return 0 on success, 1 on error (ex : ec of wrong type, etc...)
     */
    int get_key_param();
    QSignalMapper *extensionSigMap; //!< Used to map signals of delete buttons on extension table

    // Settings
    /**
     * @brief get_settings : get and apply settings
     * @param setting : setting name
     */
    void get_settings(QString setting);
    /**
     * @brief save_settings : save settgins
     * @param setting : setting name
     */
    void save_settings(QString setting);

    // network stuff for updates
    QNetworkAccessManager * network;
    int checkUpdate; //!< 0: no check, 1 check updates, 2 unknown (ask)
    /**
     * @brief check_updates unless settings say no
     */
    void check_updates();


public slots:
    //void sslfinished(); (use of  QSignalMapper).
    /**
     * @brief Gets key from Cert and display in GUI (encrypted if button checked)
     * @param error to display
     * @return 0:OK, 1: Error, 2: SSL Error
     */
    int display_generated_key(QString *errordisplay);
    void DlgGenerateKeyFinished();
    void read_callback_data();
    void DlgGenerateKeyAbort();
    void DlgGenerateKeyError(QString strError);
    void DlgGenerateCertFinished();
    void DlgGenerateCSRFinished();
    void DlgCertDateAccept(QDateTime startDate, QDateTime endDate);
    void add_extension(QString ext, QString value, bool critical);

private slots:
    void on_pushButtonGenerate_clicked();

    void on_checkBoxKeyPassEnable_stateChanged(int arg1);

    void on_pushButtonDisplayKey_clicked();

    void on_pushButtonEncryptKey_clicked();

    void on_pushButtonDecryptKey_clicked();

    void on_pushButtonGenerateCert_clicked();

    void on_pushButtonDisplayCert_clicked();

    void on_pushButtonSaveKey_clicked();

    void on_comboBoxKeyType_currentIndexChanged(const QString &arg1);

    void on_toolButtonCertValidity_clicked();

    void on_pushButtonEnableDaysLine_clicked();

    void on_pushButtonAddExtension_clicked();

    void extension_button_del_on_clicked(int index);

    void on_pushButtonLoadKey_clicked();

    void on_pushButtonSaveCert_clicked();

    void on_pushButtonLoadCert_clicked();

    void on_pushButtonTestKey_clicked();

    void on_pushButtonTestKey_2_clicked();

    void on_pushButtonSave2p12_clicked();

    void on_pushButtonSaveSettings_clicked();

    void network_reply_finished(QNetworkReply* reply);

    void on_pushButtonLoadPKCS12_clicked();

signals:
    //extension_button_del_on_clicked(int row);
    add_text_output(QString);
    finished_calc();
};


#endif // SSLMAINWINDOW_H
