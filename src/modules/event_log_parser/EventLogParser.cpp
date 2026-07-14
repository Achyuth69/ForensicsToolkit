#include "EventLogParser.h"
#include "Logger.h"
#include <QFile>
#include <QXmlStreamReader>
#include <QJsonArray>

namespace Forensic::Modules {

// Windows Event IDs
static const QMap<quint64, EventCategory> EVENT_ID_MAP = {
    {4624, EventCategory::SuccessfulLogin},
    {4625, EventCategory::FailedLogin},
    {4634, EventCategory::LogoffEvent},
    {4648, EventCategory::SuccessfulLogin},
    {4720, EventCategory::SecurityEvent},   // Account created
    {4726, EventCategory::SecurityEvent},   // Account deleted
    {4732, EventCategory::SecurityEvent},   // Added to group
    {4740, EventCategory::SecurityEvent},   // Account locked
    {4768, EventCategory::SuccessfulLogin}, // Kerberos TGT
    {4769, EventCategory::SuccessfulLogin}, // Kerberos service ticket
    {4776, EventCategory::FailedLogin},     // NTLM auth
    {6005, EventCategory::SystemEvent},     // Event log service started
    {6006, EventCategory::SystemEvent},     // Event log service stopped
    {1102, EventCategory::SecurityEvent},   // Audit log cleared
    {4688, EventCategory::ProcessExecution},
    {4689, EventCategory::ProcessTermination},
    {7034, EventCategory::ServiceEvent},    // Service crashed
    {7036, EventCategory::ServiceEvent},    // Service state change
    {1000, EventCategory::ApplicationCrash},
    {20001, EventCategory::UsbInsertion},   // New device installed
    {20003, EventCategory::UsbRemoval},
};

EventLogParser::EventLogParser(QObject *parent) : QObject(parent) {}

void EventLogParser::parseEvtxFile(const QString &evtxPath) {
    // EVTX binary format parsing
    // For portfolio: parse as XML if possible, or use exported XML
    LOG_WARN("EVTX binary parsing requires Windows API; use parseXmlExport for portable parsing.");
    parseXmlExport(evtxPath);
}

void EventLogParser::parseXmlExport(const QString &xmlPath) {
    m_entries.clear();
    m_summary = EventLogSummary{};

    QFile file(xmlPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        emit errorOccurred("Cannot open event log file: " + xmlPath);
        return;
    }

    LOG_INFO(QString("Parsing event log: %1").arg(xmlPath));

    QXmlStreamReader xml(&file);
    EventLogEntry current;
    bool inEvent = false;
    QString currentElement;
    int eventCount = 0;

    while (!xml.atEnd()) {
        xml.readNext();

        if (xml.isStartElement()) {
            currentElement = xml.name().toString();

            if (currentElement == "Event") {
                current = EventLogEntry{};
                inEvent = true;
            } else if (inEvent && currentElement == "System") {
                // parse system sub-elements
            } else if (inEvent && currentElement == "EventID") {
                // handled in characters
            } else if (inEvent && currentElement == "Data") {
                QString name = xml.attributes().value("Name").toString();
                current.data[name] = {}; // will be filled in Characters
                currentElement = "Data_" + name;
            }
        } else if (xml.isCharacters() && !xml.isWhitespace() && inEvent) {
            QString text = xml.text().toString();

            if (currentElement == "EventID")
                current.eventId = text.toULongLong();
            else if (currentElement == "Channel")
                current.logName = text;
            else if (currentElement == "Provider")
                current.source  = xml.attributes().value("Name").toString();
            else if (currentElement == "TimeCreated")
                current.timestamp = QDateTime::fromString(
                    xml.attributes().value("SystemTime").toString(), Qt::ISODate);
            else if (currentElement == "Computer")
                current.computer = text;
            else if (currentElement == "Level")
                current.severity = parseSeverity(text);
            else if (currentElement.startsWith("Data_")) {
                QString key = currentElement.mid(5);
                current.data[key] = text;
                if (key == "SubjectUserName" || key == "TargetUserName")
                    current.user = text;
                if (key == "NewProcessName" || key == "ProcessName")
                    current.data["ProcessName"] = text;
            } else if (currentElement == "Message") {
                current.message = text;
            }
        } else if (xml.isEndElement()) {
            if (xml.name().toString() == "Event" && inEvent) {
                if (current.message.isEmpty())
                    current.message = buildDefaultMessage(current);

                classifyEvent(current);
                m_entries.append(current);
                inEvent = false;
                eventCount++;

                emit progressChanged(eventCount % 100);
            }
            currentElement.clear();
        }
    }

    if (xml.hasError()) {
        LOG_WARN(QString("XML parse warning: %1").arg(xml.errorString()));
    }

    buildSummary();
    emit parseComplete(m_summary);
    LOG_INFO(QString("Event log parsed: %1 entries").arg(m_entries.size()));
}

void EventLogParser::classifyEvent(EventLogEntry &entry) {
    entry.category = classifyByEventId(entry.eventId);

    // Additional flagging logic
    if (entry.category == EventCategory::FailedLogin) {
        entry.isFlagged   = true;
        entry.flagReason  = "Failed authentication attempt";
    } else if (entry.category == EventCategory::UsbInsertion) {
        entry.isFlagged  = true;
        entry.flagReason = "Removable media inserted";
    } else if (entry.eventId == 1102) {
        entry.isFlagged  = true;
        entry.flagReason = "Security audit log was cleared – potential evidence tampering";
    } else if (entry.category == EventCategory::ProcessExecution) {
        QString proc = entry.data.value("NewProcessName").toLower();
        if (proc.contains("powershell") || proc.contains("cmd.exe") ||
            proc.contains("wscript") || proc.contains("cscript") ||
            proc.contains("mshta") || proc.contains("regsvr32")) {
            entry.isFlagged  = true;
            entry.flagReason = "Potentially suspicious process execution: " + proc;
        }
    }
}

EventCategory EventLogParser::classifyByEventId(quint64 id) {
    return EVENT_ID_MAP.value(id, EventCategory::Unknown);
}

EventSeverity EventLogParser::parseSeverity(const QString &level) {
    if (level == "1") return EventSeverity::Critical;
    if (level == "2") return EventSeverity::Error;
    if (level == "3") return EventSeverity::Warning;
    return EventSeverity::Info;
}

void EventLogParser::buildSummary() {
    for (const auto &e : m_entries) {
        m_summary.totalEvents++;
        m_summary.eventIdCounts[QString::number(e.eventId)]++;

        switch (e.category) {
        case EventCategory::FailedLogin:      m_summary.failedLogins++;     break;
        case EventCategory::SuccessfulLogin:  m_summary.successfulLogins++; break;
        case EventCategory::UsbInsertion:
        case EventCategory::UsbRemoval:       m_summary.usbEvents++;        break;
        case EventCategory::ProcessExecution: m_summary.processEvents++;    break;
        case EventCategory::ApplicationCrash: m_summary.crashes++;          break;
        case EventCategory::SecurityEvent:    m_summary.securityEvents++;   break;
        default: break;
        }

        if (!e.user.isEmpty()) m_summary.userActivityCounts[e.user]++;
        if (e.isFlagged) {
            m_summary.flaggedEvents++;
            m_summary.flaggedList.append(e);
        }
    }
}

QString EventLogParser::buildDefaultMessage(const EventLogEntry &e) const {
    switch (e.category) {
    case EventCategory::FailedLogin:
        return QString("Failed logon attempt for user: %1 on %2")
               .arg(e.user, e.computer);
    case EventCategory::SuccessfulLogin:
        return QString("Successful logon for user: %1 on %2")
               .arg(e.user, e.computer);
    case EventCategory::ProcessExecution:
        return QString("Process executed: %1 by %2")
               .arg(e.data.value("NewProcessName"), e.user);
    case EventCategory::UsbInsertion:
        return "Removable media device was connected";
    default:
        return QString("Event ID %1").arg(e.eventId);
    }
}

QList<EventLogEntry> EventLogParser::filterByCategory(EventCategory cat) const {
    QList<EventLogEntry> r;
    for (const auto &e : m_entries) if (e.category == cat) r.append(e);
    return r;
}

QList<EventLogEntry> EventLogParser::filterByUser(const QString &user) const {
    QList<EventLogEntry> r;
    for (const auto &e : m_entries) if (e.user == user) r.append(e);
    return r;
}

QList<EventLogEntry> EventLogParser::filterByTimeRange(const QDateTime &from,
                                                        const QDateTime &to) const {
    QList<EventLogEntry> r;
    for (const auto &e : m_entries)
        if (e.timestamp >= from && e.timestamp <= to) r.append(e);
    return r;
}

QJsonObject EventLogParser::toJson() const {
    QJsonArray entries;
    for (const auto &e : m_entries) {
        QJsonObject dataObj;
        for (auto it = e.data.begin(); it != e.data.end(); ++it)
            dataObj[it.key()] = it.value();

        entries.append(QJsonObject{
            {"eventId",    static_cast<qint64>(e.eventId)},
            {"logName",    e.logName},
            {"source",     e.source},
            {"timestamp",  e.timestamp.toString(Qt::ISODate)},
            {"message",    e.message},
            {"computer",   e.computer},
            {"user",       e.user},
            {"isFlagged",  e.isFlagged},
            {"flagReason", e.flagReason},
            {"data",       dataObj}
        });
    }

    QJsonObject summaryObj;
    summaryObj["totalEvents"]      = m_summary.totalEvents;
    summaryObj["failedLogins"]     = m_summary.failedLogins;
    summaryObj["successfulLogins"] = m_summary.successfulLogins;
    summaryObj["usbEvents"]        = m_summary.usbEvents;
    summaryObj["processEvents"]    = m_summary.processEvents;
    summaryObj["crashes"]          = m_summary.crashes;
    summaryObj["securityEvents"]   = m_summary.securityEvents;
    summaryObj["flaggedEvents"]    = m_summary.flaggedEvents;
    QJsonObject result;
    result["summary"] = summaryObj;
    result["entries"] = entries;
    return result;
}

} // namespace Forensic::Modules
