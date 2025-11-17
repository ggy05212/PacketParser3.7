#include "packetparser.h"
#include <QDateTime>
#include <QStringList>
#include <QDebug>

PacketParser::PacketParser(QObject *parent) : QObject(parent) {
    // 初始化Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

PacketParser::~PacketParser() {
    // 清理Winsock
    WSACleanup();
    closeFile();
}

bool PacketParser::openFile(const QString &filePath) {
    closeFile();  // 先关闭已打开的文件
    char errbuf[PCAP_ERRBUF_SIZE];
    QByteArray utf8Path = filePath.toUtf8(); // 保存临时对象，延长生命周期
    m_pcapHandle = pcap_open_offline(utf8Path.constData(), errbuf);
    if (!m_pcapHandle) {
        qWarning("无法打开pcap文件: %s", errbuf);
        return false;
    }
    // 获取原始文件的链路层类型
    m_linkType = pcap_datalink(m_pcapHandle);
    m_packetIndex = 0;
    return true;
}

void PacketParser::closeFile() {
    if (m_pcapHandle) {
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
    }
}
bool PacketParser::createOutputPcap(const QString &filePath) {
    closeOutputPcap(); // 先关闭已有的

    // 创建临时句柄用于获取数据链路层类型
    m_dumperHandle = pcap_open_dead(m_linkType, 65535); // 以太网类型，最大包长
    if (!m_dumperHandle) {
        qWarning("创建临时句柄失败");
        return false;
    }

    // 创建dumper
    m_pcapDumper = pcap_dump_open(m_dumperHandle, filePath.toUtf8().constData());
    if (!m_pcapDumper) {
        qWarning("创建pcap文件失败: %s", pcap_geterr(m_dumperHandle));
        pcap_close(m_dumperHandle);
        m_dumperHandle = nullptr;
        return false;
    }
    return true;
}

void PacketParser::writePacketToPcap(const struct pcap_pkthdr *header, const u_char *packet) {
    if (m_pcapDumper) {
//      qDebug() << "Writing packet, length:" << header->len;
        pcap_dump((u_char*)m_pcapDumper, header, packet);
    }
}

void PacketParser::closeOutputPcap() {
    if (m_pcapDumper) {
        pcap_dump_close(m_pcapDumper);
        m_pcapDumper = nullptr;
    }
    if (m_dumperHandle) {
        pcap_close(m_dumperHandle);
        m_dumperHandle = nullptr;
    }
}
void PacketParser::parseAllPackets() {
    if (!m_pcapHandle) return;

    struct pcap_pkthdr *header;  // 数据包头部（包含时间戳、长度等）
    const u_char *packet;        // 数据包内容
    int res;

    // 循环读取所有数据包
    while ((res = pcap_next_ex(m_pcapHandle, &header, &packet)) >= 0) {
        if (res == 0) continue;
        m_packetIndex++;
        PacketInfo info;
        info.index = m_packetIndex;
        // 拷贝头部信息（值拷贝）
        info.packetHeader = *header;
        // 拷贝原始数据包（按实际捕获长度 caplen 拷贝）
        info.rawData = QByteArray((const char*)packet, header->caplen);

        // 1. 解析时间戳（秒.微秒）
        QDateTime time = QDateTime::fromSecsSinceEpoch(header->ts.tv_sec);
        time = time.addMSecs(header->ts.tv_usec / 1000);  // 转换微秒到毫秒
        info.timestamp = time.toString("yyyy-MM-dd hh:mm:ss.zzz");

        // 计算与前一帧的时间差
        qint64 currentMs = time.toMSecsSinceEpoch();
        if (m_packetIndex == 1) {
            info.timeDiff = "0.000";  // 第一帧时间差为0
        } else {
            double diff = (currentMs - m_prevTimestamp) / 1000.0;  // 转换为秒
            info.timeDiff = QString::number(diff, 'f', 3);
        }
        m_prevTimestamp = currentMs;  // 保存当前时间戳用于下一帧计算


        // 计算距离首帧的时间
        qint64 currentMstofirst = time.toMSecsSinceEpoch();
        if (m_packetIndex == 1) {
            m_firstTimestamp = currentMstofirst;  // 记录首帧时间
            info.timeFromFirst = "0.000";  // 首帧距离自己的时间为0
        } else {
            double diff = (currentMstofirst - m_firstTimestamp) / 1000.0;  // 转换为秒
            info.timeFromFirst = QString::number(diff, 'f', 3);
        }
        // 2. 解析以太网层（MAC地址）
        ether_header *eth = (ether_header *)packet;
        info.srcMac = QString("%1:%2:%3:%4:%5:%6")
                .arg((uchar)eth->h_source[0], 2, 16, QChar('0'))
                .arg((uchar)eth->h_source[1], 2, 16, QChar('0'))
                .arg((uchar)eth->h_source[2], 2, 16, QChar('0'))
                .arg((uchar)eth->h_source[3], 2, 16, QChar('0'))
                .arg((uchar)eth->h_source[4], 2, 16, QChar('0'))
                .arg((uchar)eth->h_source[5], 2, 16, QChar('0')).toUpper();

        info.dstMac = QString("%1:%2:%3:%4:%5:%6")
                .arg((uchar)eth->h_dest[0], 2, 16, QChar('0'))
                .arg((uchar)eth->h_dest[1], 2, 16, QChar('0'))
                .arg((uchar)eth->h_dest[2], 2, 16, QChar('0'))
                .arg((uchar)eth->h_dest[3], 2, 16, QChar('0'))
                .arg((uchar)eth->h_dest[4], 2, 16, QChar('0'))
                .arg((uchar)eth->h_dest[5], 2, 16, QChar('0')).toUpper();
        info.protocolChain = "eth";  // 所有帧都包含以太网协议

        info.length = header->len;
        info.ethdetail = QString("0x%3").arg(ntohs(eth->h_proto), 4, 16, QChar('0')).toUpper();

        // 3. 解析网络层（IP协议）
        if (ntohs(eth->h_proto) == ETH_P_IP) {  // 确认是IP协议
            info.protocolChain += " → IP";  // 添加IP协议
            u_char *ipStart = (u_char *)(packet + sizeof(ether_header));
            ip_header *ip = (ip_header *)ipStart;


            // 解析IP版本（高4位）
            int version = (ip->version_ihl & 0xF0) >> 4;  // 提取版本号
            if (version == 4) {
                info.ipVersion = "IPv4";
            } else if (version == 6) {
                info.ipVersion = "IPv6";
            } else {
                info.ipVersion = QString("未知IP版本(%1)").arg(version);
            }


            // 检查是否为IPv4
            if ((ip->version_ihl & 0xF0) == 0x40) {  // IPv4 (版本号为4)
                // 转换IP地址格式
                char srcIpStr[INET_ADDRSTRLEN];
                char dstIpStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip->saddr, srcIpStr, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &ip->daddr, dstIpStr, INET_ADDRSTRLEN);

                info.srcIp = QString(srcIpStr);
                info.dstIp = QString(dstIpStr);
                info.ttl = (int)ip->ttl;  // 从IP头部获取TTL值
                int ipHeaderLen = (ip->version_ihl & 0x0F) * 4;  // IP头部长度


                // 4. 解析传输层（TCP/UDP）
                u_char *transportStart = ipStart + ipHeaderLen;

                if (ip->protocol == IPPROTO_TCP) {  // TCP协议
                    info.protocolChain += " → TCP";  // 添加TCP协议
                    tcp_header *tcp = (tcp_header *)transportStart;
                    info.protocol = "TCP";

                    //判断是否为SSH协议（默认端口22）
                    u_short srcPort = ntohs(tcp->src_port);
                    u_short dstPort = ntohs(tcp->dest_port);
                    if (srcPort == SSH_PORT || dstPort == SSH_PORT) {
                        info.protocol = "SSHv2";
                        info.protocolChain += " → SSH";  // 添加ssh协议
                    }

                    QString flags;
                    if (tcp->flags & TH_SYN) flags += "SYN ";
                    if (tcp->flags & TH_ACK) flags += "ACK ";

                    info.info = QString("源端口: %1, 目的端口: %2, 标志: %3")
                            .arg(ntohs(tcp->src_port))
                            .arg(ntohs(tcp->dest_port))
                            .arg(flags.trimmed());


                } else if (ip->protocol == IPPROTO_UDP) {  // UDP协议
                    info.protocolChain += " → UDP";
                    udp_header *udp = (udp_header *)transportStart;
                    info.protocol = "UDP";

                    //判断是否为SNMP协议（默认端口161/162）
                    u_short srcPort = ntohs(udp->src_port);
                    u_short dstPort = ntohs(udp->dest_port);
                    if (srcPort == SNMP_PORT || dstPort == SNMP_PORT ||
                            srcPort == SNMP_TRAP_PORT || dstPort == SNMP_TRAP_PORT) {
                        info.protocol = "SNMP";
                        info.protocolChain += " → SNMP";  // 添加SNMP协议
                    }


                    info.info = QString("源端口: %1, 目的端口: %2, 长度: %3")
                            .arg(ntohs(udp->src_port))
                            .arg(ntohs(udp->dest_port))
                            .arg(ntohs(udp->len));

                } else {
                    info.protocol = QString("IP（协议号：%1）").arg((int)ip->protocol);
                    info.protocolChain += QString(" → 协议(%1)").arg((int)ip->protocol);
                    info.info = QString("不支持的传输层协议: %1").arg((int)ip->protocol);
                }
            } else {
                info.protocol = "非IPv4";
                info.protocolChain += " → 非IPv4";
                info.info = "不支持的IP版本";
            }
        } else {
            info.protocol = QString("以太网（类型：0x%1）").arg(ntohs(eth->h_proto), 4, 16, QChar('0')).toUpper();
            info.info = "非IP协议数据包";
        }

        emit packetParsed(info);  // 发送解析结果到UI
    }

    emit parseFinished();  // 解析完成
}
