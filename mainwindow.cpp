#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QElapsedTimer>
#include <QProgressDialog>
#include <QInputDialog>
#include<QDateTime>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      m_pcapHandler(new PacketParser(this)),
      m_packetWidget(new PacketWidget(this)) {
    ui->setupUi(this);
    setWindowTitle("PCAP 阅读器");

    // 将PacketWidget设置为主窗口的中心部件
    setCentralWidget(m_packetWidget);

    // 关联信号：解析器的数据包 → 显示Widget
    connect(m_pcapHandler, &PacketParser::packetParsed, m_packetWidget, &PacketWidget::appendPacket);
    // 关联菜单和解析完成信号
    connect(ui->actionOpen, &QAction::triggered, this, &MainWindow::onActionOpenFile);
    // 设置窗口属性，使其启动时最大化
    setWindowState(Qt::WindowMaximized);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::onActionOpenFile() {
    // 选择文件
    QString filePath = QFileDialog::getOpenFileName(
                this, "选择PCAP文件", "", "PCAP Files (*.pcap *.pcapng)");
    if (filePath.isEmpty()) return;

    // 清空之前的显示
    m_packetWidget->clear();

    // 打开并解析文件
    if (m_pcapHandler->openFile(filePath)) {
        m_pcapHandler->parseAllPackets();
    } else {
        QMessageBox::critical(this, "错误", "无法打开PCAP文件！");
    }
}
void MainWindow::on_ActionTestTableLimit_triggered()
{
    m_packetWidget->clear();//清空数据
    bool ok;
    int count = QInputDialog::getInt(
        this, "测试表格极限",
        "请输入要添加的数据包数量:",
        10000, 1000, 1000000, 10000, &ok
    );
    if(!ok) return;
    QProgressDialog progress("正在添加数据包","取消",0,count,this);
    progress.setWindowTitle("测试中...");
    progress.setWindowModality(Qt::WindowModal);
    progress.show();
    QElapsedTimer timer;
    timer.start();

    // 生成并添加模拟数据包
       for (int i = 0; i < count; ++i) {
           if (progress.wasCanceled()) break;
           progress.setValue(i);

           PacketInfo mockInfo;
           // 填充模拟数据（尽量接近真实数据格式，减少内存占用）
           mockInfo.index = i + 1;
           mockInfo.timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz");
           mockInfo.timeDiff = QString::number((i % 100) / 100.0, 'f', 3);
           mockInfo.timeFromFirst = QString::number(i / 1000.0, 'f', 3);
           mockInfo.srcMac = QString("AA:BB:CC:DD:EE:%1").arg(i % 256, 2, 16, QChar('0')).toUpper();
           mockInfo.dstMac = QString("FF:EE:DD:CC:BB:%1").arg(i % 256, 2, 16, QChar('0')).toUpper();
           mockInfo.srcIp = QString("192.168.%1.%2").arg((i / 256) % 256).arg(i % 256);
           mockInfo.dstIp = QString("10.0.%1.%2").arg((i / 256) % 256).arg(i % 256);
           mockInfo.protocol = (i % 2 == 0) ? "TCP" : "UDP";
           mockInfo.length = 100 + (i % 1400);  // 随机长度（100-1500字节）
           mockInfo.info = QString("测试数据包 %1").arg(i + 1);
           mockInfo.ethdetail = "0x0800";  // 模拟IP协议
           mockInfo.protocolChain = "eth → IP → " + mockInfo.protocol;
           mockInfo.ipVersion = "IPv4";
           mockInfo.ttl = 64 + (i % 64);
           mockInfo.rawData = QByteArray(mockInfo.length, 'a');  // 模拟原始数据
           // 简化头部（仅填充必要字段）
           mockInfo.packetHeader.len = mockInfo.length;
           mockInfo.packetHeader.caplen = mockInfo.length;

           //添加表格
           m_packetWidget->appendPacket(mockInfo);
           // 每1000行刷新一次界面，避免卡顿
//            if (i % 1000 == 0) {
//                QApplication::processEvents();  // 处理事件队列
//            }
        }

        progress.setValue(count);
        qint64 elapsed = timer.elapsed();
        QMessageBox::information(
            this, "测试完成",
            QString("添加了 %1 行数据，耗时 %2 毫秒\n"
                    "请观察内存占用和界面响应").arg(count).arg(elapsed)
        );
}
