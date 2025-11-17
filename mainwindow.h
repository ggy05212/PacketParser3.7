#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "packetparser.h"
#include "packetwidget.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onActionOpenFile();                  // 打开文件
    void on_ActionTestTableLimit_triggered();//测试

private:
    Ui::MainWindow *ui;
    PacketParser *m_pcapHandler;         // 数据包处理器
    PacketWidget *m_packetWidget;       // 显示用的Widget
};
#endif // MAINWINDOW_H
