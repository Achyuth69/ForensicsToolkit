#include "ForensicCase.h"
#include <QJsonArray>
#include <QUuid>

namespace Forensic::Core {

// ─── Investigator ─────────────────────────────────────────────────────────────
QJsonObject Investigator::toJson() const {
    return {
        {"id",         id},
        {"name",       name},
        {"email",      email},
        {"badge",      badge},
        {"role",       role},
        {"assignedAt", assignedAt.toString(Qt::ISODate)}
    };
}

Investigator Investigator::fromJson(const QJsonObject &obj) {
    Investigator inv;
    inv.id         = obj["id"].toString();
    inv.name       = obj["name"].toString();
    inv.email      = obj["email"].toString();
    inv.badge      = obj["badge"].toString();
    inv.role       = obj["role"].toString();
    inv.assignedAt = QDateTime::fromString(obj["assignedAt"].toString(), Qt::ISODate);
    return inv;
}

// ─── EvidenceItem ─────────────────────────────────────────────────────────────
QJsonObject EvidenceItem::toJson() const {
    return {
        {"id",               id},
        {"caseId",           caseId},
        {"label",            label},
        {"filePath",         filePath},
        {"hash",             hash},
        {"type",             type},
        {"sizeBytes",        sizeBytes},
        {"acquiredAt",       acquiredAt.toString(Qt::ISODate)},
        {"acquiredBy",       acquiredBy},
        {"chainOfCustody",   chainOfCustody},
        {"verified",         verified}
    };
}

EvidenceItem EvidenceItem::fromJson(const QJsonObject &obj) {
    EvidenceItem e;
    e.id             = obj["id"].toString();
    e.caseId         = obj["caseId"].toString();
    e.label          = obj["label"].toString();
    e.filePath       = obj["filePath"].toString();
    e.hash           = obj["hash"].toString();
    e.type           = obj["type"].toString();
    e.sizeBytes      = obj["sizeBytes"].toVariant().toLongLong();
    e.acquiredAt     = QDateTime::fromString(obj["acquiredAt"].toString(), Qt::ISODate);
    e.acquiredBy     = obj["acquiredBy"].toString();
    e.chainOfCustody = obj["chainOfCustody"].toString();
    e.verified       = obj["verified"].toBool();
    return e;
}

// ─── ForensicCase ─────────────────────────────────────────────────────────────
QString ForensicCase::statusString() const {
    switch (status) {
    case CaseStatus::Open:       return "Open";
    case CaseStatus::InProgress: return "In Progress";
    case CaseStatus::Closed:     return "Closed";
    case CaseStatus::Archived:   return "Archived";
    }
    return "Unknown";
}

QJsonObject ForensicCase::toJson() const {
    QJsonArray invArr, evArr, noteArr;

    for (auto &inv  : investigators) invArr.append(inv.toJson());
    for (auto &ev   : evidence)      evArr.append(ev.toJson());
    for (auto &note : notes) {
        noteArr.append(QJsonObject{
            {"id",        note.id},
            {"caseId",    note.caseId},
            {"authorId",  note.authorId},
            {"content",   note.content},
            {"createdAt", note.createdAt.toString(Qt::ISODate)},
            {"updatedAt", note.updatedAt.toString(Qt::ISODate)}
        });
    }

    return {
        {"id",            id},
        {"title",         title},
        {"description",   description},
        {"caseNumber",    caseNumber},
        {"status",        statusString()},
        {"createdAt",     createdAt.toString(Qt::ISODate)},
        {"updatedAt",     updatedAt.toString(Qt::ISODate)},
        {"investigators", invArr},
        {"evidence",      evArr},
        {"notes",         noteArr},
        {"reportPath",    reportPath}
    };
}

ForensicCase ForensicCase::fromJson(const QJsonObject &obj) {
    ForensicCase c;
    c.id          = obj["id"].toString();
    c.title       = obj["title"].toString();
    c.description = obj["description"].toString();
    c.caseNumber  = obj["caseNumber"].toString();
    c.createdAt   = QDateTime::fromString(obj["createdAt"].toString(), Qt::ISODate);
    c.updatedAt   = QDateTime::fromString(obj["updatedAt"].toString(), Qt::ISODate);
    c.reportPath  = obj["reportPath"].toString();

    QString s = obj["status"].toString();
    if      (s == "Open")        c.status = CaseStatus::Open;
    else if (s == "In Progress") c.status = CaseStatus::InProgress;
    else if (s == "Closed")      c.status = CaseStatus::Closed;
    else if (s == "Archived")    c.status = CaseStatus::Archived;

    for (auto v : obj["investigators"].toArray())
        c.investigators.append(Investigator::fromJson(v.toObject()));
    for (auto v : obj["evidence"].toArray())
        c.evidence.append(EvidenceItem::fromJson(v.toObject()));
    for (auto v : obj["notes"].toArray()) {
        auto no = v.toObject();
        CaseNote note;
        note.id        = no["id"].toString();
        note.caseId    = no["caseId"].toString();
        note.authorId  = no["authorId"].toString();
        note.content   = no["content"].toString();
        note.createdAt = QDateTime::fromString(no["createdAt"].toString(), Qt::ISODate);
        note.updatedAt = QDateTime::fromString(no["updatedAt"].toString(), Qt::ISODate);
        c.notes.append(note);
    }
    return c;
}

} // namespace Forensic::Core
