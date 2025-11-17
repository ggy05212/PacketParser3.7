#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <QObject>
#include <QString>
#include <pcap.h>

#pragma pack(push, 1)

// 以太网帧头部
typedef struct ether_header {
    u_char  h_dest[6];    // 目的MAC地址（6字节）
    u_char  h_source[6];  // 源MAC地址（6字节）
    u_short h_proto;      // 上层协议类型（2字节)
} ether_header;


typedef struct ip_header {
    u_char  version_ihl;  // 版本号(4位) + 头部长度(4位)（1字节）
    u_char  tos;          // 服务类型（1字节）
    u_short total_len;    // 数据包总长度（2字节）
    u_short id;           // 标识（2字节）
    u_short frag_off;     // 分片偏移（2字节）
    u_char  ttl;          // 生存时间（1字节）
    u_char  protocol;     // 上层协议（1字节）
    u_short check;        // 校验和（2字节）
    struct in_addr saddr; // 源IP地址（4字节）
    struct in_addr daddr; // 目的IP地址（4字节）
} ip_header;

// TCP段头部
typedef struct tcp_header {
    u_short src_port;     // 源端口（2字节）
    u_short dest_port;    // 目的端口（2字节）
    u_int   seq;          // 序列号（4字节）
    u_int   ack;          // 确认号（4字节）
    u_char  data_off;     // 数据偏移（4位）+ 保留位（4位）（1字节）
    u_char  flags;        // 标志位（1字节）
    u_short window;       // 窗口大小（2字节）
    u_short check;        // 校验和（2字节）
    u_short urgent_ptr;   // 紧急指针（2字节）
} tcp_header;

// UDP段头部
typedef struct udp_header {
    u_short src_port;     // 源端口（2字节）
    u_short dest_port;    // 目的端口（2字节）
    u_short len;          // UDP段总长度（2字节）
    u_short check;        // 校验和（2字节）
} udp_header;

// 恢复默认对齐方式
#pragma pack(pop)

// -------------------------- 协议常量定义 --------------------------
#define ETH_P_IP   0x0800  // 以太网帧类型：IP协议
#define ETH_P_ARP  0x0806  // 以太网帧类型：ARP协议
#define IPPROTO_TCP 6      // IP协议类型：TCP协议
#define IPPROTO_UDP 17     // IP协议类型：UDP协议

#define SSH_PORT 22       // SSH默认端口
#define SNMP_PORT 161     // SNMP默认端口
#define SNMP_TRAP_PORT 162 // SNMP陷阱端口

// TCP标志位定义
#define TH_SYN 0x02        // SYN标志
#define TH_ACK 0x10        // ACK标志

// -------------------------- 数据包信息存储结构 --------------------------
struct PacketInfo {
    int index;               // 数据包序号（自增）
    QString timestamp;       // 时间戳（格式：yyyy-MM-dd hh:mm:ss.zzz）
    QString timeDiff;        // 与前一帧的时间差(毫秒)
    QString timeFromFirst;   // 距离首帧时间(秒)
    QString srcMac;          // 源MAC地址（格式：AA:BB:CC:DD:EE:FF）
    QString dstMac;          // 目的MAC地址（同上）
    QString srcIp;           // 源IP地址（格式：xxx.xxx.xxx.xxx）
    QString dstIp;           // 目的IP地址（同上）
    QString protocol;        // 协议类型（如：Ethernet、IP、TCP、UDP）
    int length;              // 数据包总长度（字节）
    QString info;            // 摘要信息（如：TCP SYN、UDP端口信息）
    QString ethdetail;       // 以太网层详细信息（协议类型）
    QString protocolChain;   // 帧中包含的所有协议链
    QString ipVersion;       // IP版本
    int ttl;                 //生存时间
    QByteArray rawData;          // 存储原始数据包拷贝
    struct pcap_pkthdr packetHeader; // 存储头部拷贝（不再是指针）
    QByteArray payloadData;  // 载荷原始数据
    QString payloadHex;      // 载荷的十六进制表示
    QString payloadAscii;    // 载荷的ASCII表示（可打印字符）

    // TCP相关字段（新增）
    int tcpSrcPort;       // TCP源端口
    int tcpDstPort;       // TCP目的端口
    quint32 tcpSeq;       // TCP序列号
    quint32 tcpAck;       // TCP确认号
    QString tcpFlags;     // TCP标志位（如SYN、ACK）
    int tcpWindow;        // TCP窗口大小
    int tcpChecksum;      // TCP校验和
    bool hasTcpInfo=false;      // 是否包含TCP信息

    // UDP相关字段（新增）
    int udpSrcPort;       // UDP源端口
    int udpDstPort;       // UDP目的端口
    int udpLength;        // UDP总长度
    int udpChecksum;      // UDP校验和
    bool hasUdpInfo=false;      // 是否包含UDP信息

};

// -------------------------- 解析器类定义 --------------------------
class PacketParser : public QObject {
    Q_OBJECT
public:
    bool createOutputPcap(const QString &filePath); // 创建输出pcap文件
    void writePacketToPcap(const struct pcap_pkthdr *header, const u_char *packet); // 写入数据包
    void closeOutputPcap(); // 关闭输出文件
    explicit PacketParser(QObject *parent = nullptr);  // 构造函数（先声明）
    ~PacketParser();                                   // 析构函数（后声明，符合C++语法）
    bool openFile(const QString &filePath);            // 打开pcap文件（返回成功/失败）
    void closeFile();                                  // 关闭pcap文件（释放句柄）
    void parseAllPackets();                            // 解析所有数据包（循环读取）

signals:
    void packetParsed(const PacketInfo &info);  // 解析到单个数据包时触发（传递信息）
    void parseFinished();                       // 所有数据包解析完成时触发

private:
    pcap_t *m_pcapHandle = nullptr;  // pcap文件句柄（初始化为空）
    int m_packetIndex = 0;           // 数据包序号计数器（初始化为0）
    qint64 m_prevTimestamp = 0;      // 上一帧的时间戳(毫秒)
    qint64 m_firstTimestamp = -1;    // 首帧时间戳(毫秒，-1表示未初始化)
    pcap_dumper_t *m_pcapDumper = nullptr; // pcap写入句柄
    pcap_t *m_dumperHandle = nullptr;     // 用于创建dumper的临时句柄
    int m_linkType;  // 链路层类型（如DLT_EN10MB）
};

#endif // PACKETPARSER_H
