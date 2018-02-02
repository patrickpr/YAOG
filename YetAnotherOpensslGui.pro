#-------------------------------------------------
#   Project : Yet Another OpenSSL GUI
#   Author : Patrick Proy
#   Copyright (C) 2016
#
#   Licence : http://www.gnu.org/licenses/gpl.txt
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = YetAnotherOpensslGui
TEMPLATE = app

SOURCES +=  src/app/main.cpp\
            src/app/sslmainwindow.cpp \
            src/app/sslcertificates.cpp \
            src/app/dialoggeneratekey.cpp \
            src/app/dialogsslerrors.cpp \
            src/app/dialogcertdate.cpp \
            src/app/dialogx509v3extention.cpp \
    src/app/cdialogpkcs12.cpp

HEADERS  += src/app/sslmainwindow.h \
            src/app/sslcertificates.h \
            src/app/dialoggeneratekey.h \
            src/app/dialogsslerrors.h \
            src/app/dialogcertdate.h \
            src/app/dialogx509v3extention.h \
    src/app/cdialogpkcs12.h

FORMS    += src/app/sslmainwindow.ui \
            src/app/dialoggeneratekey.ui \
            src/app/dialogsslerrors.ui \
            src/app/dialogcertdate.ui \
            src/app/dialogx509v3extention.ui \
    src/app/cdialogpkcs12.ui

LIBS += -L"D:\apps\Dev\OpenSSL-Win32\lib\MinGW"
LIBS += "D:\apps\Dev\OpenSSL-Win32\lib\MinGW\libssl-1_1.a" "D:\apps\Dev\OpenSSL-Win32\lib\MinGW\libcrypto-1_1.a"
#LIBS += -L"D:\apps\Dev\OpenSSL-Win32_1.0.2\lib\MinGW" -leay32 -lssleay32

INCLUDEPATH += "D:\apps\Dev\OpenSSL-Win32\include"
#INCLUDEPATH += "D:\apps\Dev\OpenSSL-Win32_1.0.2\include"
