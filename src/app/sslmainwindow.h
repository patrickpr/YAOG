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
#include <QSslSocket>
#include <QDebug>

#include <QtNetwork>
#include "sslcertificates.h"
#include "dialoggeneratekey.h"
#include "dialogsslerrors.h"
#include "dialogcertdate.h"
#include "dialogx509v3extention.h"
#include "cdialogpkcs12.h"
#include "stackwindow.h"

#define YAOGVERSION "1.1.2"
#define YAOGVERSIONF "01010200"
#define YAOGPLATFORM "W64"
#define UPDATESRC "https://www.proy.org/yaog/update.php"

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
    /**
     * @brief create_csr_from_key
     * Key must be loaded into cert structure
     */
    void create_csr_from_key();

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


/**
 * @brief The SSLMainWindow class
 * App Main window
 */
class SSLMainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit SSLMainWindow(QWidget *parent = nullptr);
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
    static void CB_add_data(const char *data);
    /**
     * @brief Read and erase existing string in buffer CBdata
     * @return message from openssl
     */
    static QString CB_read_data();

    // For stack import

    /**
     * @brief Import key
     * @param key QString : key in pem format
     */
    void import_key(QString key);

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
     * @brief delete_extension and erase it from the widget table
     * @param value of index of extension element as this is called throught a signal mapping
     */
    void delete_extension(int index);
    /**
     * @brief delete_All_extensions Delete all extensions
     */
    void delete_All_extensions();
    /**
     * @brief addExtensionLine : adds extension in the wdget table
     * @param elmt to add
     */
    void addExtensionLine(extensionElmt* elmt);

private:
    Ui::SSLMainWindow *ui;

    // Certificate stuff
    SSLCertificates *Cert;
    void init_cert(); //!< initialise this->Cert
    void init_cert(SSLCertificates **newCert); //!< creates a new cert and catches errors.
    SSLCertificates* getCert(); //!< create if null and returns Cert
    void deleteCert(); //!< delete this->Cert object and set to nullptr
    void deleteCert(SSLCertificates **newCert); //!< delete newCert object and set to nullptr
    int push_cert_options(SSLCertificates* cert);//!< push name,options,digest to cert
    int push_cert_validity(SSLCertificates* cert);//!< push date to cert

    int cert_output_type; //!< PEM in textDisplay is cert/csr...
    QDateTime CertStartDate; //!< Certificate start date
    QDateTime CertEndDate; //!< Certificate end date

    // Certificate stack
    CStackWindow * stackWindow;

    // Key and cert generation thread and display
    DialogGenerateKey* DlgGenerateKey;
    QThread* SSLthread;
    SSLWorker* sslworker;
    void create_async_dialog(QString title);
    void flush_async_dialog();
    void close_async_dialog();
    QTimer *timer; //!< used to read data in static function

    void display_cert(QString cert,bool update=false); //!< display "cert" in textEdit and set to update elements in main window if update=true;
    void display_key(QString key, bool update=false); //!< display "key" in textEdit and set to update elements in main window if update=true;
    bool cert_update,key_update; //!< used to block updates on changes. set to false by display_cert/key and reset by onTextChange slots
    // PKCS12 stuff
    CDialogPKCS12* dlgP12;

    /**
     * @brief read_pem_to_openssl reads the key in window and puts it in openssl structure
     * @param keySrc QString : pem encoded key
     * @param keyDst SSLCertificates* : wher to put key
     * @return  0: success , 1: ssl error, 2: password error, 3: unknown key
     */
    int read_pem_to_openssl(QString keySrc, SSLCertificates* keyDst);
    /**
     * @brief read_pem_to_openssl reads the key in window and puts it in openssl structure
     * Cert must be allocated
     * asks password if needed.
     * @param cert SSLCertificate* : if not nullptr, put in this structure
     * @return 0: success , 1: ssl error, 2: password error, 3: unknown key
     */
    int read_pem_to_openssl(SSLCertificates* cert=nullptr);
    /**
     * @brief read_cert_pem_to_openssl reads the cert in window and puts it in openssl structure
     * @param certType SSLCertificates::certType : type (csr / cert)
     * @param certSrc QString : cert in pem format
     * @param certDst SSLCertificate* : where to put it.
     * @return  0: success , 1: ssl error, 2: password error
     */
    int read_cert_pem_to_openssl(SSLCertificates::certType certType,QString certSrc, SSLCertificates* certDst);
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
    void display_ssl_err(QString message, SSLCertificates *key=nullptr);
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
     * @return QString key name;
     */
    QString display_key_type(SSLCertificates* key=nullptr);
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
    int checkUpdate; //!< 0: no check, 1 check updates, 3 unknown (ask)
    int checkUpdateNum; //!< number of times before warning user again about updates
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

    void DlgPKCS12_Finished(bool Cancel, bool MainCertImport, int caCertImport);
    void network_reply_finished(QNetworkReply* reply);
    void network_reply_SSL_error(QNetworkReply* reply,QList<QSslError> SSLErr);
    /**
     * @brief Import certificate
     * @param certificate CertData
     */
    void import_cert_key(CStackWindow::CertData certificate);


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

    void on_pushButtonLoadPKCS12_clicked();

    void on_pushButtonOpenStack_clicked();

    void on_pushButtonPushCert_clicked();

    void on_pushButtonSignCert_clicked();

    void on_textEditCert_textChanged();

    void on_textEditKey_textChanged();

signals:
    //extension_button_del_on_clicked(int row);
    void add_text_output(QString);
    void finished_calc();
};

#define USER_ALL_PASSWORDS_FOUND "nice" // you DID check this
#endif // SSLMAINWINDOW_H
