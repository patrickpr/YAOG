#-------------------------------------------------
#
# Project created by QtCreator 2016-04-17T15:48:17
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = YetAnotherOpensslGui
TEMPLATE = app

SOURCES += src/app/main.cpp\
        src/app/sslmainwindow.cpp \
    src/app/sslcertificates.cpp \
    src/app/dialoggeneratekey.cpp \
    src/app/dialogsslerrors.cpp \
    src/app/dialogcertdate.cpp \
    src/app/dialogx509v3extention.cpp

HEADERS  += src/app/sslmainwindow.h \
    src/app/sslcertificates.h \
    src/app/dialoggeneratekey.h \
    src/app/dialogsslerrors.h \
    src/app/dialogcertdate.h \
    src/app/dialogx509v3extention.h

FORMS    += src/app/sslmainwindow.ui \
    src/app/dialoggeneratekey.ui \
    src/app/dialogsslerrors.ui \
    src/app/dialogcertdate.ui \
    src/app/dialogx509v3extention.ui

LIBS += -L"../YetAnotherOpensslGui/src/openssl/lib/MinGW" -leay32 -lssleay32

INCLUDEPATH += "src/openssl/include"
