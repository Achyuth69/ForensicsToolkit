#include "NetworkForensics.h"
#include "Logger.h"
#include <QFile>
#include <QDataStream>
#include <QJsonArray>
#include <algorithm>

namespace Forensic::Modules {

// ─── PCAP file format constants ───────────────────────────────────────────────
static constexpr quint32 PCAP_MAGIC_LE    = 0xA1B2C3D4;
static constexpr quint32 PCAP_MAGIC_BE    = 0xD4C3B2A1;
static constexpr quint32 PCAP_MAGIC_NS_LE = 0xA1B23C4D;

#pragma pack(push, 1)
struct PcapGlobalHeader {
    quint32 magic_number;
    quint16 version_major;
    quint16 version_minor;
    qint32  thiszone;
    quint32 sigfigs;
    quint32 snaplen;
    quint32 network;
};
struct PcapRecordHeader {
    quint32 ts_sec;
    quint32 ts_usec;
    quint32 incl_len;
    quint32 orig_len;
};
#pragma pack(pop)

NetworkForensics::NetworkForensics(QObject *parent) : QObject(parent) {}

void NetworkForensics::loadPcap(const QString &pcapPath) {
    m_cancelled.store(false);
    m_packets.clear();
    m_dns.clear();
    m_http.clear();
    m_summary = NetworkSummary{};

    LOG_INFO(QString("Loading PCAP: %1").arg(pcapPath));
    emit progressChanged(5, "Opening file...");

    QFile file(pcapPath);
    if (!file.open(QIODevice::ReadOnly)) {
        emit errorOccurred("Cannot open PCAP file: " + pcapPath);
        return;
    }

    QByteArray data = file.readAll();
    file.close();

    emit progressChanged(15, "Parsing packets...");
    parsePcapNative(pcapPath);

    emit progressChanged(80, "Building summary...");
    buildSummary();

    emit progressChanged(100, "Done");
    emit analysisComplete(m_summary);
    LOG_INFO(QString("PCAP loaded: %1 packets").arg(m_packets.size()));
}

void NetworkForensics::parsePcapNative(const QString &path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return;

    // Read global header
    PcapGlobalHeader gh;
    if (f.read(reinterpret_cast<char*>(&gh), sizeof(gh)) != sizeof(gh)) return;

    bool swapped = (gh.magic_number == PCAP_MAGIC_BE);
    bool nsecs   = (gh.magic_number == PCAP_MAGIC_NS_LE);

    quint64 pktNum = 1;

    while (!f.atEnd() && !m_cancelled.load()) {
        PcapRecordHeader rh;
        if (f.read(reinterpret_cast<char*>(&rh), sizeof(rh)) != sizeof(rh)) break;

        if (swapped) {
            rh.ts_sec  = qbswap(rh.ts_sec);
            rh.ts_usec = qbswap(rh.ts_usec);
            rh.incl_len= qbswap(rh.incl_len);
            rh.orig_len= qbswap(rh.orig_len);
        }

        if (rh.incl_len > 65535) break; // safety

        QByteArray payload = f.read(rh.incl_len);
        if (payload.size() < static_cast<int>(rh.incl_len)) break;

        Packet pkt;
        pkt.number  = pktNum++;
        pkt.length  = static_cast<int>(rh.orig_len);
        pkt.payload = payload;

        qint64 ts = static_cast<qint64>(rh.ts_sec) * 1000
                  + (nsecs ? rh.ts_usec / 1000000 : rh.ts_usec / 1000);
        pkt.timestamp = QDateTime::fromMSecsSinceEpoch(ts);

        // Parse Ethernet frame (link type 1)
        if (payload.size() < 14) { m_packets.append(pkt); continue; }

        quint16 etherType = (static_cast<unsigned char>(payload[12]) << 8)
                          |  static_cast<unsigned char>(payload[13]);

        // IPv4 = 0x0800
        if (etherType == 0x0800 && payload.size() >= 34) {
            const unsigned char *ip = reinterpret_cast<const unsigned char*>(payload.constData()) + 14;
            int ihl = (ip[0] & 0x0F) * 4;
            quint8 proto = ip[9];

            pkt.srcIp = QString("%1.%2.%3.%4").arg(ip[12]).arg(ip[13]).arg(ip[14]).arg(ip[15]);
            pkt.dstIp = QString("%1.%2.%3.%4").arg(ip[16]).arg(ip[17]).arg(ip[18]).arg(ip[19]);

            if (static_cast<int>(payload.size()) >= 14 + ihl + 4) {
                const unsigned char *tp = ip + ihl;
                pkt.srcPort = (tp[0] << 8) | tp[1];
                pkt.dstPort = (tp[2] << 8) | tp[3];

                if (proto == 6)  pkt.protocol = Protocol::TCP;
                else if (proto == 17) pkt.protocol = Protocol::UDP;

                pkt.protocol = detectProtocol(pkt.srcPort, pkt.dstPort, payload);

                // Parse DNS (UDP port 53)
                if ((pkt.srcPort == 53 || pkt.dstPort == 53) &&
                    payload.size() > 14 + ihl + 12) {
                    DnsRecord dns;
                    dns.srcIp     = pkt.srcIp;
                    dns.timestamp = pkt.timestamp;
                    // Extract query name from DNS payload
                    const unsigned char *dnsData = tp + 8;
                    int remaining = payload.size() - (14 + ihl + 8);
                    if (remaining > 4) {
                        QString name;
                        int idx = 0;
                        while (idx < remaining && dnsData[idx] != 0) {
                            int len = dnsData[idx++];
                            for (int i = 0; i < len && idx < remaining; i++, idx++)
                                name += QChar(dnsData[idx]);
                            if (dnsData[idx] != 0) name += '.';
                        }
                        dns.query = name;
                        dns.type  = "A";
                        if (!name.isEmpty()) m_dns.append(dns);
                    }
                }

                // Parse HTTP
                if ((pkt.dstPort == 80 || pkt.srcPort == 80) && proto == 6) {
                    QByteArray tcpPayload = payload.mid(14 + ihl + ((tp[12] >> 4) * 4));
                    if (tcpPayload.startsWith("GET ") || tcpPayload.startsWith("POST ") ||
                        tcpPayload.startsWith("PUT ") || tcpPayload.startsWith("HEAD ")) {
                        HttpSession hs;
                        hs.srcIp    = pkt.srcIp;
                        hs.dstIp    = pkt.dstIp;
                        hs.timestamp= pkt.timestamp;
                        QList<QByteArray> lines = tcpPayload.split('\n');
                        if (!lines.isEmpty()) {
                            QList<QByteArray> req = lines[0].split(' ');
                            if (req.size() >= 2) {
                                hs.method = req[0];
                                hs.url    = req[1];
                            }
                        }
                        for (int li = 1; li < lines.size(); li++) {
                            QByteArray line = lines[li].trimmed();
                            if (line.startsWith("Host:"))
                                hs.host = line.mid(5).trimmed();
                            if (line.startsWith("User-Agent:"))
                                hs.userAgent = line.mid(11).trimmed();
                        }
                        m_http.append(hs);
                    }
                }
            }
        }

        pkt.isSuspicious = isSuspiciousHost(pkt.dstIp);
        m_packets.append(pkt);

        if (pktNum % 1000 == 0)
            emit progressChanged(qMin(79, 15 + static_cast<int>(pktNum / 100)), "Parsing...");
    }
}

Protocol NetworkForensics::detectProtocol(quint16 src, quint16 dst,
                                           const QByteArray &payload) {
    Q_UNUSED(payload)
    if (src == 53 || dst == 53)   return Protocol::DNS;
    if (src == 80 || dst == 80)   return Protocol::HTTP;
    if (src == 443 || dst == 443) return Protocol::HTTPS;
    if (src == 25 || dst == 25)   return Protocol::SMTP;
    if (src == 21 || dst == 21)   return Protocol::FTP;
    if (src == 20 || dst == 20)   return Protocol::FTP;
    return Protocol::TCP;
}

bool NetworkForensics::isSuspiciousHost(const QString &host) {
    static const QStringList suspicious = {
        "tor2web", ".onion", "pastebin.com", "raw.githubusercontent.com",
        "ngrok.io", "serveo.net", "duckdns.org", "no-ip.com"
    };
    for (const auto &s : suspicious) if (host.contains(s)) return true;
    return false;
}

void NetworkForensics::buildSummary() {
    m_summary.totalPackets = m_packets.size();

    for (const auto &pkt : m_packets) {
        m_summary.totalBytes += pkt.length;
        if (pkt.protocol == Protocol::TCP)  m_summary.tcpPackets++;
        if (pkt.protocol == Protocol::UDP)  m_summary.udpPackets++;
        if (pkt.protocol == Protocol::DNS)  m_summary.dnsQueries++;
        if (pkt.protocol == Protocol::HTTP) m_summary.httpRequests++;
        if (pkt.isSuspicious)               m_summary.suspiciousPackets++;

        if (!pkt.srcIp.isEmpty()) m_summary.topSrcIps[pkt.srcIp]++;
        if (!pkt.dstIp.isEmpty()) m_summary.topDstIps[pkt.dstIp]++;
        if (pkt.isSuspicious && !pkt.dstIp.isEmpty())
            m_summary.suspiciousHosts.append(pkt.dstIp);

        if (m_summary.firstPacket.isNull() || pkt.timestamp < m_summary.firstPacket)
            m_summary.firstPacket = pkt.timestamp;
        if (m_summary.lastPacket.isNull() || pkt.timestamp > m_summary.lastPacket)
            m_summary.lastPacket = pkt.timestamp;
    }

    for (const auto &dns : m_dns)
        if (!dns.query.isEmpty()) m_summary.topDomains[dns.query]++;
}

QList<Packet> NetworkForensics::filterByIp(const QString &ip) const {
    QList<Packet> r;
    for (const auto &p : m_packets)
        if (p.srcIp == ip || p.dstIp == ip) r.append(p);
    return r;
}

QList<Packet> NetworkForensics::filterByProtocol(Protocol proto) const {
    QList<Packet> r;
    for (const auto &p : m_packets)
        if (p.protocol == proto) r.append(p);
    return r;
}

void NetworkForensics::cancel() { m_cancelled.store(true); }

QJsonObject NetworkForensics::toJson() const {
    QJsonObject sum{
        {"totalPackets",     m_summary.totalPackets},
        {"tcpPackets",       m_summary.tcpPackets},
        {"udpPackets",       m_summary.udpPackets},
        {"dnsQueries",       m_summary.dnsQueries},
        {"httpRequests",     m_summary.httpRequests},
        {"suspiciousPackets",m_summary.suspiciousPackets},
        {"totalBytes",       m_summary.totalBytes},
        {"firstPacket",      m_summary.firstPacket.toString(Qt::ISODate)},
        {"lastPacket",       m_summary.lastPacket.toString(Qt::ISODate)}
    };

    QJsonObject topSrc, topDst, topDom;
    for (auto it = m_summary.topSrcIps.begin(); it != m_summary.topSrcIps.end(); ++it)
        topSrc[it.key()] = it.value();
    for (auto it = m_summary.topDstIps.begin(); it != m_summary.topDstIps.end(); ++it)
        topDst[it.key()] = it.value();
    for (auto it = m_summary.topDomains.begin(); it != m_summary.topDomains.end(); ++it)
        topDom[it.key()] = it.value();

    sum["topSrcIps"]  = topSrc;
    sum["topDstIps"]  = topDst;
    sum["topDomains"] = topDom;

    QJsonArray suspHosts;
    for (const auto &h : m_summary.suspiciousHosts) suspHosts.append(h);
    sum["suspiciousHosts"] = suspHosts;

    return QJsonObject{{"summary", sum}};
}

} // namespace Forensic::Modules
