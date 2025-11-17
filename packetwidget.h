#ifndef PACKETWIDGET_H
#define PACKETWIDGET_H

#include <QWidget>
#include <QTreeWidgetItem>
#include "packetparser.h"

namespace Ui {
class PacketWidget;
}

class PacketWidget : public QWidget {
    Q_OBJECT

public:
    explicit PacketWidget(QWidget *parent = nullptr);
    ~PacketWidget();
    void clear();
    void cleardetail();

public slots:
    void appendPacket(const PacketInfo &data);
    void onTableItemClicked(int row, int column);
    void onSaveFilteredClicked(); // 保存筛选数据

private slots:
    // 根据选中的IP过滤表格行
    void filterTableByIp(int index);
    void filterTableByProtocol(int index); //协议筛选

private:
    QSet<QString> m_protocols; // 存储协议类型
    QSet<QString> m_ipAddresses;//存储ip
    void updateIpComboBox();//更新下拉框
    void updateProtocolComboBox(); // 新增：更新协议下拉框
    Ui::PacketWidget *ui;
    QList<PacketInfo> m_packetList;
    // 新增：将详细信息转换为树状结构
    void buildDetailTree(const PacketInfo &info);
    QString formatHexData(const QByteArray &data);  // 声明16进制转换函数

};

#endif // PACKETWIDGET_H
