#pragma once
#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QJsonObject>
#include <QDateTime>
#include <atomic>

namespace Forensic::Modules {

enum class Protocol { TCP, UDP, DNS, HTTP, HTTPS, SMTP, FTP, ICMP, ARP, Unknown };

struct Packet {
    quint64   number{0};
    QDateTime timestamp;
    Protocol  protocol{Protocol::Unknown};
    QString   srcIp;
    quint16   srcPort{0};
    QString   dstIp;
    quint16   dstPort{0};
    int       length{0};
    QString   info;
    QByteArray payload;
    bool      isSuspicious{false};
};

struct DnsRecord {
    QString   query;
    QString   response;
    QString   type;
    QDateTime timestamp;
    QString   srcIp;
};

struct HttpSession {
    QString   method;
    QString   url;
    QString   host;
    QString   userAgent;
    int       statusCode{0};
    QString   contentType;
    QString   srcIp;
    QString   dstIp;
    QDateTime timestamp;
    QByteArray requestBody;
    QByteArray responseBody;
};

struct NetworkSummary {
    int                   totalPackets{0};
    int                   tcpPackets{0};
    int                   udpPackets{0};
    int                   dnsQueries{0};
    int                   httpRequests{0};
    int                   suspiciousPackets{0};
    QMap<QString, int>    topSrcIps;
    QMap<QString, int>    topDstIps;
    QMap<QString, int>    topDomains;
    QList<QString>        suspiciousHosts;
    qint64                totalBytes{0};
    QDateTime             firstPacket;
    QDateTime             lastPacket;
};

class NetworkForensics : public QObject {
    Q_OBJECT
public:
    explicit NetworkForensics(QObject *parent = nullptr);

    void loadPcap(const QString &pcapPath);
    void cancel();

    const QList<Packet>&      packets()     const { return m_packets;  }
    const QList<DnsRecord>&   dnsRecords()  const { return m_dns;      }
    const QList<HttpSession>& httpSessions()const { return m_http;     }
    const NetworkSummary&     summary()     const { return m_summary;  }
    QJsonObject               toJson()      const;

    // Filter helpers
    QList<Packet> filterByIp(const QString &ip) const;
    QList<Packet> filterByProtocol(Protocol p)  const;

signals:
    void progressChanged(int percent, const QString &stage);
    void analysisComplete(const NetworkSummary &summary);
    void errorOccurred(const QString &error);

private:
    void parsePcapNative(const QString &path);
    void parsePackets(const QByteArray &data);
    Protocol detectProtocol(quint16 srcPort, quint16 dstPort, const QByteArray &payload);
    bool isSuspiciousHost(const QString &host);
    void buildSummary();

    QList<Packet>      m_packets;
    QList<DnsRecord>   m_dns;
    QList<HttpSession> m_http;
    NetworkSummary     m_summary;
    std::atomic<bool>  m_cancelled{false};
};

} // namespace Forensic::Modules
