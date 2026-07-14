#pragma once
#include <QObject>
#include <QString>
#include <QList>
#include <QDateTime>
#include <QJsonObject>
#include <QMap>

namespace Forensic::Modules {

enum class EventSeverity { Info, Warning, Error, Critical };

enum class EventCategory {
    FailedLogin, SuccessfulLogin, LogoffEvent,
    UsbInsertion, UsbRemoval,
    ProcessExecution, ProcessTermination,
    ApplicationCrash, ServiceEvent,
    SecurityEvent, SystemEvent,
    FileAccess, NetworkEvent,
    Unknown
};

struct EventLogEntry {
    quint64       eventId{0};
    QString       logName;
    QString       source;
    EventSeverity severity{EventSeverity::Info};
    EventCategory category{EventCategory::Unknown};
    QDateTime     timestamp;
    QString       message;
    QString       computer;
    QString       user;
    QMap<QString, QString> data;
    bool          isFlagged{false};
    QString       flagReason;
};

struct EventLogSummary {
    int totalEvents{0};
    int failedLogins{0};
    int successfulLogins{0};
    int usbEvents{0};
    int processEvents{0};
    int crashes{0};
    int securityEvents{0};
    int flaggedEvents{0};
    QMap<QString, int>    eventIdCounts;
    QMap<QString, int>    userActivityCounts;
    QList<EventLogEntry>  flaggedList;
};

class EventLogParser : public QObject {
    Q_OBJECT
public:
    explicit EventLogParser(QObject *parent = nullptr);

    /// Parse a binary EVTX file. Falls back to parseXmlExport on non-Windows.
    void parseEvtxFile(const QString &evtxPath);

    /// Parse XML exported from Windows Event Viewer (File → Save All Events As XML).
    void parseXmlExport(const QString &xmlPath);

    const QList<EventLogEntry>& entries() const { return m_entries; }
    const EventLogSummary&      summary() const { return m_summary; }
    QJsonObject                 toJson()  const;

    QList<EventLogEntry> filterByCategory(EventCategory cat) const;
    QList<EventLogEntry> filterByUser(const QString &user)   const;
    QList<EventLogEntry> filterByTimeRange(const QDateTime &from,
                                            const QDateTime &to) const;

signals:
    void progressChanged(int percent);
    void parseComplete(const EventLogSummary &summary);
    void errorOccurred(const QString &error);

private:
    void          classifyEvent(EventLogEntry &entry);
    void          buildSummary();
    EventCategory classifyByEventId(quint64 id);
    EventSeverity parseSeverity(const QString &level);
    QString       buildDefaultMessage(const EventLogEntry &e) const;

    QList<EventLogEntry> m_entries;
    EventLogSummary      m_summary;
};

} // namespace Forensic::Modules
