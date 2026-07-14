#pragma once
#include <QString>
#include <QDateTime>
#include <QUuid>
#include <QList>
#include <QJsonObject>

namespace Forensic::Core {

enum class CaseStatus { Open, InProgress, Closed, Archived };

struct Investigator {
    QString id;
    QString name;
    QString email;
    QString badge;
    QString role;
    QDateTime assignedAt;

    QJsonObject toJson() const;
    static Investigator fromJson(const QJsonObject &obj);
};

struct EvidenceItem {
    QString id;
    QString caseId;
    QString label;
    QString filePath;
    QString hash;          // SHA-256
    QString type;          // disk_image | memory_dump | pcap | evtx | file
    qint64  sizeBytes{0};
    QDateTime acquiredAt;
    QString acquiredBy;
    QString chainOfCustody;
    bool    verified{false};

    QJsonObject toJson() const;
    static EvidenceItem fromJson(const QJsonObject &obj);
};

struct CaseNote {
    QString    id;
    QString    caseId;
    QString    authorId;
    QString    content;
    QDateTime  createdAt;
    QDateTime  updatedAt;
};

struct ForensicCase {
    QString          id;
    QString          title;
    QString          description;
    QString          caseNumber;
    CaseStatus       status{CaseStatus::Open};
    QDateTime        createdAt;
    QDateTime        updatedAt;
    QList<Investigator>  investigators;
    QList<EvidenceItem>  evidence;
    QList<CaseNote>      notes;
    QString          reportPath;

    QJsonObject toJson() const;
    static ForensicCase fromJson(const QJsonObject &obj);
    QString statusString() const;
};

} // namespace Forensic::Core
