#include "packetparser.h"
#include <QDateTime>
#include <QStringList>
#include <QDebug>
#include <QtGlobal>
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
                    // 提取TCP字段（新增）
                    info.hasTcpInfo = true;
                    info.tcpSrcPort = ntohs(tcp->src_port);
                    info.tcpDstPort = ntohs(tcp->dest_port);
                    info.tcpSeq = ntohl(tcp->seq);       // 序列号（网络字节序转主机）
                    info.tcpAck = ntohl(tcp->ack);       // 确认号
                    info.tcpWindow = ntohs(tcp->window); // 窗口大小
                    info.tcpChecksum = ntohs(tcp->check); // 校验和

                    // 解析TCP标志位（SYN、ACK等）
                    QString flags;
                    if (tcp->flags & TH_SYN) flags += "SYN ";
                    if (tcp->flags & TH_ACK) flags += "ACK ";
                    if (tcp->flags & 0x01) flags += "FIN ";   // FIN标志
                    if (tcp->flags & 0x04) flags += "RST ";   // RST标志
                    if (tcp->flags & 0x08) flags += "PSH ";   // PSH标志
                    if (tcp->flags & 0x20) flags += "URG ";   // URG标志

                    info.info = QString("源端口: %1, 目的端口: %2, 标志: %3")
                            .arg(ntohs(tcp->src_port))
                            .arg(ntohs(tcp->dest_port))
                            .arg(flags.trimmed());

                    // 计算TCP头部长度（数据偏移字段 * 4）
                       int tcpHeaderLen = (tcp->data_off >> 4) * 4;
                       // 载荷起始位置 = 以太网头部 + IP头部 + TCP头部
                       const u_char* payloadStart = transportStart + tcpHeaderLen;
                       // 载荷长度 = 数据包总长度 - 已解析的头部长度
                       int payloadLen = header->caplen - (payloadStart - packet);

                       // 提取载荷数据
                       info.payloadData = QByteArray((const char*)payloadStart, payloadLen);


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

                    // 提取UDP字段（新增）
                     info.hasUdpInfo = true;
                     info.udpSrcPort = ntohs(udp->src_port);
                     info.udpDstPort = ntohs(udp->dest_port);
                     info.udpLength = ntohs(udp->len);     // 总长度（头部+数据）
                     info.udpChecksum = ntohs(udp->check); // 校验和


                    info.info = QString("源端口: %1, 目的端口: %2, 长度: %3")
                            .arg(ntohs(udp->src_port))
                            .arg(ntohs(udp->dest_port))
                            .arg(ntohs(udp->len));


                    // UDP头部固定8字节，载荷起始位置 = UDP头部结束处
                       const u_char* payloadStart = transportStart + sizeof(udp_header);
                       // 载荷长度 = UDP总长度 - UDP头部长度（8字节）
                       int udpTotalLen = ntohs(udp->len);

                       qint64 val1 = qint64(udpTotalLen) - sizeof(udp_header);
                       qint64 val2 = qint64(header->caplen) - (payloadStart - packet);

                       // 确保长度非负（避免计算错误导致的负数），再取最小值
                       int payloadLen = qMin(
                           static_cast<int>(qMax(val1, 0LL)),  // 0LL确保是long long类型，与qint64匹配
                           static_cast<int>(qMax(val2, 0LL))
                       );
                       // 提取载荷数据
                       info.payloadData = QByteArray((const char*)payloadStart, payloadLen);

                       // 转换载荷为十六进制和ASCII格式
                       // 十六进制：每字节用2位十六进制表示，空格分隔
                       QString hexStr;
                       // ASCII：可打印字符直接显示，不可打印字符用.代替
                       QString asciiStr;
                       for (int i = 0; i < info.payloadData.size(); ++i) {
                           u_char c = (u_char)info.payloadData[i];
                           hexStr += QString("%1 ").arg(c, 2, 16, QChar('0')).toUpper();
                           asciiStr += (c >= 32 && c <= 126) ? QChar(c) : '.';

                           // 每16字节换行，方便阅读
                           if ((i + 1) % 16 == 0) {
                               hexStr += "\n";
                               asciiStr += "\n";
                           }
                       }
                       info.payloadHex = hexStr.trimmed();
                       info.payloadAscii = asciiStr.trimmed();

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
