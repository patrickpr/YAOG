#include "sslmainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    SSLMainWindow w;
    w.show();
    return a.exec();
}
