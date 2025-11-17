#-------------------------------------------------
#
# Project created by QtCreator 2025-10-30T10:10:39
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = PacketParser3
TEMPLATE = app

# -------------- 编译警告与兼容性配置 --------------
# 启用 Qt 废弃 API 警告（帮助后续升级）
DEFINES += QT_DEPRECATED_WARNINGS
# 屏蔽 CRT 安全函数警告（如 sprintf、strcpy）
DEFINES += _CRT_SECURE_NO_WARNINGS
# 屏蔽 Winsock 旧函数警告（如 inet_addr）
DEFINES += _WINSOCK_DEPRECATED_NO_WARNINGS
# 启用 Windows Vista 及以上 API（确保 inet_ntop 等函数可用）
DEFINES += _WIN32_WINNT=0x0600

# -------------- 源文件、头文件、UI 文件列表 --------------

SOURCES += \
        main.cpp \
        mainwindow.cpp \
    packetparser.cpp \
    packetwidget.cpp

HEADERS += \
        mainwindow.h \
    packetparser.h \
    packetwidget.h

FORMS += \
        mainwindow.ui \
    packetwidget.ui
# -------------- Npcap SDK 配置（核心） --------------
# Npcap SDK 头文件路径
INCLUDEPATH += "D:\\Npcap-SDK\\Include"

# Npcap 库文件路径
LIBS += -L"D:\Npcap-SDK\Lib\x64"

# 链接 Npcap 必需库（wpcap：核心抓包，packet：底层数据包处理）
LIBS += -lwpcap -lpacket

# -------------- Windows 网络库（必需） --------------
# 链接 Winsock 2 库
win32: LIBS += -lws2_32

# -------------- 可选：调试信息配置（推荐） --------------
# 启用调试信息（方便调试时查看变量和调用栈）
QMAKE_CXXFLAGS_DEBUG += -g
QMAKE_LFLAGS_DEBUG += -g

