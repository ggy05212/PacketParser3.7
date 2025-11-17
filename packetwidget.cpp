#include "packetwidget.h"
#include "ui_packetwidget.h"
#include <QTableWidgetItem>
#include<QFileDialog>
#include<QMessageBox>

PacketWidget::PacketWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketWidget) {
    ui->setupUi(this);

    // 初始化表格
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setColumnCount(6);
    ui->tableWidget->setHorizontalHeaderLabels(
    {"序号", "时间戳", "源地址", "目的地址", "协议", "信息"});
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    connect(ui->tableWidget, &QTableWidget::itemClicked, this, [=](QTableWidgetItem *item) {
        if (item) {
            onTableItemClicked(item->row(), item->column());
        }
    });

    // 初始化树状结构
    //    ui->detailTree->setHeaderLabel("数据包详细信息");
    ui->detailTree->setColumnCount(2);
    ui->detailTree->setHeaderLabels({"字段", "值"});


    // 初始化IP地址下拉框
    ui->ipComboBox->setEditable(false);
    ui->ipComboBox->addItem("所有IP地址");

    // 绑定ComboBox选择变化信号到过滤函数
    connect(ui->ipComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PacketWidget::filterTableByIp);
    connect(ui->m_saveButton, &QPushButton::clicked, this, &PacketWidget::onSaveFilteredClicked);
    // 绑定协议筛选信号
    connect(ui->protocolComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),this, &PacketWidget::filterTableByProtocol);
}

PacketWidget::~PacketWidget() {
    delete ui;
}

void PacketWidget::cleardetail() {
    ui->tableWidget->setRowCount(0);
    m_packetList.clear();
    ui->detailTree->clear(); // 清空树状结构
}

void PacketWidget::clear() {
    ui->tableWidget->setRowCount(0);
}

void PacketWidget::appendPacket(const PacketInfo &data) {
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    ui->tableWidget->setItem(row, 0, new QTableWidgetItem(QString::number(data.index)));
    ui->tableWidget->setItem(row, 1, new QTableWidgetItem(data.timestamp));
    ui->tableWidget->setItem(row, 2, new QTableWidgetItem(data.srcIp.isEmpty() ? data.srcMac : data.srcIp));
    ui->tableWidget->setItem(row, 3, new QTableWidgetItem(data.dstIp.isEmpty() ? data.dstMac : data.dstIp));
    ui->tableWidget->setItem(row, 4, new QTableWidgetItem(data.protocol));
    ui->tableWidget->setItem(row, 5, new QTableWidgetItem(data.info));
    m_packetList.append(data);



    // 收集IP地址
    if (!data.srcIp.isEmpty() && data.srcIp != "0.0.0.0") {
        m_ipAddresses.insert(data.srcIp);
    }
    if (!data.dstIp.isEmpty() && data.dstIp != "0.0.0.0") {
        m_ipAddresses.insert(data.dstIp);
    }

    // 更新IP下拉框
    updateIpComboBox();

    // 收集协议类型
    if (!data.protocol.isEmpty()) {
        m_protocols.insert(data.protocol);
    }

    // 更新IP和协议下拉框
    updateIpComboBox();
    updateProtocolComboBox();
}

// 构建树状结构
void PacketWidget::buildDetailTree(const PacketInfo &info) {
    ui->detailTree->clear();
    // 基本信息节点
    QTreeWidgetItem *baseItem = new QTreeWidgetItem({"物理层的数据帧概况"});
    baseItem->addChild(new QTreeWidgetItem({"序号", QString::number(info.index)}));
    baseItem->addChild(new QTreeWidgetItem({"时间戳", info.timestamp}));
    baseItem->addChild(new QTreeWidgetItem({"与前一帧时间差", info.timeDiff + " 秒"}));
    baseItem->addChild(new QTreeWidgetItem({"距离首帧时间", info.timeFromFirst + " 秒"}));
    baseItem->addChild(new QTreeWidgetItem({"总长度", QString::number(info.length)+"bytes"}));
    baseItem->addChild(new QTreeWidgetItem({"帧中包含的协议", info.protocolChain}));

    ui->detailTree->addTopLevelItem(baseItem);

    // 以太网层节点
    QTreeWidgetItem *ethItem = new QTreeWidgetItem({"数据链路层以太网帧头部信息"});
    ethItem->addChild(new QTreeWidgetItem({"源MAC", info.srcMac}));
    ethItem->addChild(new QTreeWidgetItem({"目的MAC", info.dstMac}));
    ethItem->addChild(new QTreeWidgetItem({"详细信息",info.ethdetail}));
    ui->detailTree->addTopLevelItem(ethItem);

    // IP层节点
    if (!info.srcIp.isEmpty()) {
        QTreeWidgetItem *ipItem = new QTreeWidgetItem({"互联网层IP包头部信息"});
        ipItem->addChild(new QTreeWidgetItem({"版本", info.ipVersion}));
        ipItem->addChild(new QTreeWidgetItem({"源IP", info.srcIp}));
        ipItem->addChild(new QTreeWidgetItem({"目的IP", info.dstIp}));
        ipItem->addChild(new QTreeWidgetItem({"协议", info.protocol}));
        ipItem->addChild(new QTreeWidgetItem({"TTL", QString::number(info.ttl)}));  // 显示TTL
        ui->detailTree->addTopLevelItem(ipItem);
    }

    if (info.hasTcpInfo) {
           QTreeWidgetItem *tcpItem = new QTreeWidgetItem({"TCP层"});
           tcpItem->addChild(new QTreeWidgetItem({"源端口", QString::number(info.tcpSrcPort)}));
           tcpItem->addChild(new QTreeWidgetItem({"目的端口", QString::number(info.tcpDstPort)}));
           tcpItem->addChild(new QTreeWidgetItem({"序列号", QString::number(info.tcpSeq)}));
           tcpItem->addChild(new QTreeWidgetItem({"确认号", QString::number(info.tcpAck)}));
           tcpItem->addChild(new QTreeWidgetItem({"标志位", info.tcpFlags}));
           tcpItem->addChild(new QTreeWidgetItem({"窗口大小", QString::number(info.tcpWindow)}));
           tcpItem->addChild(new QTreeWidgetItem({"校验和", QString("0x%1").arg(info.tcpChecksum, 4, 16, QChar('0')).toUpper()}));
           ui->detailTree->addTopLevelItem(tcpItem);
       }

       // 新增：UDP层节点（如果有UDP信息）
       if (info.hasUdpInfo) {
           QTreeWidgetItem *udpItem = new QTreeWidgetItem({"UDP层"});
           udpItem->addChild(new QTreeWidgetItem({"源端口", QString::number(info.udpSrcPort)}));
           udpItem->addChild(new QTreeWidgetItem({"目的端口", QString::number(info.udpDstPort)}));
           udpItem->addChild(new QTreeWidgetItem({"总长度", QString::number(info.udpLength) + " 字节（含头部8字节）"}));
           udpItem->addChild(new QTreeWidgetItem({"校验和", QString("0x%1").arg(info.udpChecksum, 4, 16, QChar('0')).toUpper()}));
           ui->detailTree->addTopLevelItem(udpItem);
       }



    if (!info.payloadData.isEmpty()) {
          QTreeWidgetItem *payloadItem = new QTreeWidgetItem({"数据载荷"});
          payloadItem->addChild(new QTreeWidgetItem({"载荷长度", QString("%1 字节").arg(info.payloadData.size())}));

          // 十六进制视图
          QTreeWidgetItem *hexItem = new QTreeWidgetItem({"十六进制"});
          hexItem->addChild(new QTreeWidgetItem({info.payloadHex}));  // 子节点显示十六进制内容
          payloadItem->addChild(hexItem);

          // ASCII视图
          QTreeWidgetItem *asciiItem = new QTreeWidgetItem({"ASCII"});
          asciiItem->addChild(new QTreeWidgetItem({info.payloadAscii}));  // 子节点显示ASCII内容
          payloadItem->addChild(asciiItem);

          ui->detailTree->addTopLevelItem(payloadItem);
      } else {
          // 无载荷数据时添加提示
          QTreeWidgetItem *payloadItem = new QTreeWidgetItem({"数据载荷", "无载荷数据"});
          ui->detailTree->addTopLevelItem(payloadItem);
      }

    // 展开所有节点
    ui->detailTree->expandAll();

    ui->hexDisplay->setText(formatHexData(info.rawData));

}

QString PacketWidget::formatHexData(const QByteArray &data)
{
    if (data.isEmpty()) return "无数据";

      QString hexStr;
      // 每行显示16个字节
      const int bytesPerLine = 16;

      for (int i = 0; i < data.size(); i += bytesPerLine) {
          // 偏移地址（16进制，8位）
          hexStr += QString("%1  ").arg(i, 8, 16, QChar('0')).toUpper();

          // 16进制数据部分
          int lineEnd = qMin(i + bytesPerLine, data.size());
          for (int j = i; j < lineEnd; ++j) {
              hexStr += QString("%1 ").arg((uchar)data[j], 2, 16, QChar('0')).toUpper();
          }

          // 补充空格使ASCII部分对齐
          int spaceCount = (bytesPerLine - (lineEnd - i)) * 3;
          hexStr += QString(spaceCount, ' ');

          // ASCII字符部分（可打印字符显示，其他显示'.'）
          for (int j = i; j < lineEnd; ++j) {
              uchar c = (uchar)data[j];
              hexStr += (c >= 32 && c <= 126) ? QChar(c) : '.';
          }

          hexStr += "\n";  // 换行
      }

      return hexStr;
}

void PacketWidget::onTableItemClicked(int row, int column) {
    Q_UNUSED(column);
    if (row >= 0 && row < m_packetList.size()) {
        const PacketInfo &info = m_packetList[row];
        buildDetailTree(info); // 显示树状结构
    }
}

void PacketWidget::onSaveFilteredClicked()
{
    QString filePath = QFileDialog::getSaveFileName(
                this, "保存筛选结果", "", "PCAP Files (*.pcap)");
    if (filePath.isEmpty()) return;



    // 获取PacketParser实例（从MainWindow传递或通过信号）
    PacketParser *parser = qobject_cast<PacketParser*>(parent()->findChild<PacketParser*>());
    if (!parser || !parser->createOutputPcap(filePath)) {
        QMessageBox::critical(this, "错误", "无法创建输出文件");
        return;
    }

    // 遍历所有可见行（筛选后的数据）
    for (int row = 0; row < ui->tableWidget->rowCount(); ++row) {
        if (!ui->tableWidget->isRowHidden(row) && row < m_packetList.size()) {
            const PacketInfo &info = m_packetList[row];
            parser->writePacketToPcap(&info.packetHeader,(const u_char*)info.rawData.constData());
        }
    }

    parser->closeOutputPcap();
    QMessageBox::information(this, "完成", "筛选结果已保存");
}


// 更新IP地址下拉框
void PacketWidget::updateIpComboBox() {
    // 保存当前选中项
    QString currentText = ui->ipComboBox->currentText();

    // 先清空现有项（保留"所有IP地址"）
    ui->ipComboBox->clear();
    ui->ipComboBox->addItem("所有IP地址");

    // 添加收集到的IP地址（排序后显示）
    QList<QString> sortedIps = m_ipAddresses.toList();
    std::sort(sortedIps.begin(), sortedIps.end());
    ui->ipComboBox->addItems(sortedIps);

    // 恢复选中项
    int index = ui->ipComboBox->findText(currentText);
    if (index >= 0) {
        ui->ipComboBox->setCurrentIndex(index);
    }
}
void PacketWidget::filterTableByIp(int index) {
    // 1. 获取选中的IP（处理边界情况）
    if (index < 0 || index >= ui->ipComboBox->count()) {
        return; // 无效索引，直接返回
    }
    QString targetIp = ui->ipComboBox->itemText(index);

    // 2. 如果选择"所有IP地址"，显示所有行
    if (targetIp == "所有IP地址") {
        for (int row = 0; row < ui->tableWidget->rowCount(); ++row) {
            ui->tableWidget->setRowHidden(row, false);
        }
        return;
    }

    // 3. 过滤逻辑：只显示源IP或目的IP匹配的行
    for (int row = 0; row < ui->tableWidget->rowCount(); ++row) {
        // 安全检查：避免表格单元格为空导致的空指针崩溃
        QTableWidgetItem* srcItem = ui->tableWidget->item(row, 2); // 源地址列（第3列）
        QTableWidgetItem* dstItem = ui->tableWidget->item(row, 3); // 目的地址列（第4列）
        if (!srcItem || !dstItem) {
            ui->tableWidget->setRowHidden(row, true); // 单元格为空时隐藏
            continue;
        }

        // 提取源IP和目的IP（支持MAC地址与IP共存的情况）
        QString src = srcItem->text();
        QString dst = dstItem->text();

        // 判断是否匹配（源IP或目的IP等于目标IP）
        bool isMatch = (src == targetIp) || (dst == targetIp);

        // 控制行的显示/隐藏
        ui->tableWidget->setRowHidden(row, !isMatch);
    }
}
void PacketWidget::updateProtocolComboBox() {
    QString currentText = ui->protocolComboBox->currentText();

    ui->protocolComboBox->clear();
    ui->protocolComboBox->addItem("所有协议");

    // 排序并添加协议类型
    QList<QString> sortedProtocols = m_protocols.toList();
    std::sort(sortedProtocols.begin(), sortedProtocols.end());
    ui->protocolComboBox->addItems(sortedProtocols);

    // 恢复选中项
    int index = ui->protocolComboBox->findText(currentText);
    if (index >= 0) {
        ui->protocolComboBox->setCurrentIndex(index);
    }
}

// 协议筛选逻辑
void PacketWidget::filterTableByProtocol(int index) {
    if (index < 0 || index >= ui->protocolComboBox->count()) {
        return;
    }
    QString targetProtocol = ui->protocolComboBox->itemText(index);

    // 显示所有协议
    if (targetProtocol == "所有协议") {
        for (int row = 0; row < ui->tableWidget->rowCount(); ++row) {
            ui->tableWidget->setRowHidden(row, false);
        }
        return;
    }

    // 筛选指定协议
    for (int row = 0; row < ui->tableWidget->rowCount(); ++row) {
        QTableWidgetItem* protoItem = ui->tableWidget->item(row, 4);
        if (!protoItem) {
            ui->tableWidget->setRowHidden(row, true);
            continue;
        }

        // 协议匹配则显示
        bool isMatch = (protoItem->text() == targetProtocol);
        ui->tableWidget->setRowHidden(row, !isMatch);
    }
}
