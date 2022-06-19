#-------------------------------------------------
#
# Project created by QtCreator 2018-11-19T17:54:16
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = GPacketAnalyzer
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11 -static

SOURCES += \
        main.cpp \
        mainwindow.cpp \
    UDP_Manager.cpp \
    Telnet_Manager.cpp \
    TCP_Manager.cpp \
    IP_Manager.cpp \
    HTTP_Manager.cpp \
    FTP_Manager.cpp \
    EthernetManager.cpp \
    DNS_Manager.cpp \
    promiscdialog.cpp \
    information.cpp

HEADERS += \
        mainwindow.h \
    UDP_Manager.h \
    Telnet_Manager.h \
    TCP_Manager.h \
    IP_Manager.h \
    HTTP_Manager.h \
    FTP_Manager.h \
    EthernetManager.h \
    DNS_Manager.h \
    promiscdialog.h \
    information.h

FORMS += \
        mainwindow.ui \
    promiscdialog.ui \
    information.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    resource.qrc
