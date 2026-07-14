#include "CaseRepository.h"
#include "Logger.h"
#include <QSqlError>
#include <QSqlQuery>
#include <QVariant>
#include <QUuid>
#include <QJsonDocument>

namespace Forensic::Services {

CaseRepository::CaseRepository(const QString &dbPath) {
    m_db = QSqlDatabase::addDatabase("QSQLITE", "forensic_" + dbPath);
    m_db.setDatabaseName(dbPath);
    if (!m_db.open()) {
        m_lastError = m_db.lastError().text();
        LOG_ERROR("DB open failed: " + m_lastError);
    } else {
        initSchema();
    }
}

CaseRepository::~CaseRepository() {
    QString connName = m_db.connectionName();
    m_db.close();
    QSqlDatabase::removeDatabase(connName);
}

bool CaseRepository::isOpen() const { return m_db.isOpen(); }

bool CaseRepository::initSchema() {
    QStringList ddl = {
        R"(CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            case_number TEXT,
            status TEXT DEFAULT 'Open',
            created_at TEXT,
            updated_at TEXT,
            report_path TEXT
        ))",
        R"(CREATE TABLE IF NOT EXISTS investigators (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            badge TEXT,
            role TEXT,
            assigned_at TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        ))",
        R"(CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            label TEXT NOT NULL,
            file_path TEXT,
            hash TEXT,
            type TEXT,
            size_bytes INTEGER DEFAULT 0,
            acquired_at TEXT,
            acquired_by TEXT,
            chain_of_custody TEXT,
            verified INTEGER DEFAULT 0,
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        ))",
        R"(CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            author_id TEXT,
            content TEXT,
            created_at TEXT,
            updated_at TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        ))",
        "PRAGMA foreign_keys = ON",
        "PRAGMA journal_mode = WAL"
    };

    for (const auto &sql : ddl) {
        QSqlQuery q(m_db);
        if (!q.exec(sql)) {
            m_lastError = q.lastError().text();
            LOG_ERROR("Schema init failed: " + m_lastError);
            return false;
        }
    }
    return true;
}

// ─── Cases ────────────────────────────────────────────────────────────────────
bool CaseRepository::insert(const Forensic::Core::ForensicCase &c) {
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO cases(id,title,description,case_number,status,created_at,updated_at,report_path)"
        " VALUES(?,?,?,?,?,?,?,?)");
    q.addBindValue(c.id);
    q.addBindValue(c.title);
    q.addBindValue(c.description);
    q.addBindValue(c.caseNumber);
    q.addBindValue(c.statusString());
    q.addBindValue(c.createdAt.toString(Qt::ISODate));
    q.addBindValue(c.updatedAt.toString(Qt::ISODate));
    q.addBindValue(c.reportPath);
    if (!q.exec()) { m_lastError = q.lastError().text(); return false; }

    for (const auto &inv : c.investigators)  insertInvestigator(c.id, inv);
    for (const auto &ev  : c.evidence)       insertEvidence(ev);
    for (const auto &n   : c.notes)          insertNote(n);
    return true;
}

bool CaseRepository::update(const Forensic::Core::ForensicCase &c) {
    QSqlQuery q(m_db);
    q.prepare(
        "UPDATE cases SET title=?,description=?,case_number=?,status=?,updated_at=?,report_path=?"
        " WHERE id=?");
    q.addBindValue(c.title);
    q.addBindValue(c.description);
    q.addBindValue(c.caseNumber);
    q.addBindValue(c.statusString());
    q.addBindValue(c.updatedAt.toString(Qt::ISODate));
    q.addBindValue(c.reportPath);
    q.addBindValue(c.id);
    if (!q.exec()) { m_lastError = q.lastError().text(); return false; }
    return true;
}

bool CaseRepository::remove(const QString &id) {
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM cases WHERE id=?");
    q.addBindValue(id);
    if (!q.exec()) { m_lastError = q.lastError().text(); return false; }
    return true;
}

std::optional<Forensic::Core::ForensicCase> CaseRepository::find(const QString &id) const {
    QSqlQuery q(m_db);
    q.prepare("SELECT * FROM cases WHERE id=?");
    q.addBindValue(id);
    if (!q.exec() || !q.next()) return std::nullopt;

    Forensic::Core::ForensicCase c = rowToCase(q);
    c.investigators = investigatorsForCase(id);
    c.evidence      = evidenceForCase(id);
    c.notes         = notesForCase(id);
    return c;
}

QList<Forensic::Core::ForensicCase> CaseRepository::findAll() const {
    QSqlQuery q(m_db);
    q.exec("SELECT * FROM cases ORDER BY created_at DESC");
    QList<Forensic::Core::ForensicCase> list;
    while (q.next()) {
        auto c = rowToCase(q);
        c.investigators = investigatorsForCase(c.id);
        c.evidence      = evidenceForCase(c.id);
        c.notes         = notesForCase(c.id);
        list.append(c);
    }
    return list;
}

Forensic::Core::ForensicCase CaseRepository::rowToCase(const QSqlQuery &q) const {
    Forensic::Core::ForensicCase c;
    c.id          = q.value("id").toString();
    c.title       = q.value("title").toString();
    c.description = q.value("description").toString();
    c.caseNumber  = q.value("case_number").toString();
    c.reportPath  = q.value("report_path").toString();
    c.createdAt   = QDateTime::fromString(q.value("created_at").toString(), Qt::ISODate);
    c.updatedAt   = QDateTime::fromString(q.value("updated_at").toString(), Qt::ISODate);
    QString s = q.value("status").toString();
    if      (s == "Open")        c.status = Forensic::Core::CaseStatus::Open;
    else if (s == "In Progress") c.status = Forensic::Core::CaseStatus::InProgress;
    else if (s == "Closed")      c.status = Forensic::Core::CaseStatus::Closed;
    else if (s == "Archived")    c.status = Forensic::Core::CaseStatus::Archived;
    return c;
}

// ─── Evidence ─────────────────────────────────────────────────────────────────
bool CaseRepository::insertEvidence(const Forensic::Core::EvidenceItem &e) {
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT OR REPLACE INTO evidence(id,case_id,label,file_path,hash,type,"
        "size_bytes,acquired_at,acquired_by,chain_of_custody,verified)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)");
    q.addBindValue(e.id);
    q.addBindValue(e.caseId);
    q.addBindValue(e.label);
    q.addBindValue(e.filePath);
    q.addBindValue(e.hash);
    q.addBindValue(e.type);
    q.addBindValue(e.sizeBytes);
    q.addBindValue(e.acquiredAt.toString(Qt::ISODate));
    q.addBindValue(e.acquiredBy);
    q.addBindValue(e.chainOfCustody);
    q.addBindValue(e.verified ? 1 : 0);
    if (!q.exec()) { m_lastError = q.lastError().text(); return false; }
    return true;
}

bool CaseRepository::removeEvidence(const QString &id) {
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM evidence WHERE id=?");
    q.addBindValue(id);
    return q.exec();
}

bool CaseRepository::updateEvidenceVerified(const QString &id, bool verified) {
    QSqlQuery q(m_db);
    q.prepare("UPDATE evidence SET verified=? WHERE id=?");
    q.addBindValue(verified ? 1 : 0);
    q.addBindValue(id);
    return q.exec();
}

QList<Forensic::Core::EvidenceItem> CaseRepository::evidenceForCase(const QString &caseId) const {
    QSqlQuery q(m_db);
    q.prepare("SELECT * FROM evidence WHERE case_id=?");
    q.addBindValue(caseId);
    q.exec();
    QList<Forensic::Core::EvidenceItem> list;
    while (q.next()) {
        Forensic::Core::EvidenceItem e;
        e.id             = q.value("id").toString();
        e.caseId         = q.value("case_id").toString();
        e.label          = q.value("label").toString();
        e.filePath       = q.value("file_path").toString();
        e.hash           = q.value("hash").toString();
        e.type           = q.value("type").toString();
        e.sizeBytes      = q.value("size_bytes").toLongLong();
        e.acquiredAt     = QDateTime::fromString(q.value("acquired_at").toString(), Qt::ISODate);
        e.acquiredBy     = q.value("acquired_by").toString();
        e.chainOfCustody = q.value("chain_of_custody").toString();
        e.verified       = q.value("verified").toBool();
        list.append(e);
    }
    return list;
}

// ─── Investigators ────────────────────────────────────────────────────────────
bool CaseRepository::insertInvestigator(const QString &caseId,
                                         const Forensic::Core::Investigator &inv) {
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT OR REPLACE INTO investigators(id,case_id,name,email,badge,role,assigned_at)"
        " VALUES(?,?,?,?,?,?,?)");
    q.addBindValue(inv.id);
    q.addBindValue(caseId);
    q.addBindValue(inv.name);
    q.addBindValue(inv.email);
    q.addBindValue(inv.badge);
    q.addBindValue(inv.role);
    q.addBindValue(inv.assignedAt.toString(Qt::ISODate));
    return q.exec();
}

bool CaseRepository::removeInvestigator(const QString &id) {
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM investigators WHERE id=?");
    q.addBindValue(id);
    return q.exec();
}

QList<Forensic::Core::Investigator> CaseRepository::investigatorsForCase(const QString &caseId) const {
    QSqlQuery q(m_db);
    q.prepare("SELECT * FROM investigators WHERE case_id=?");
    q.addBindValue(caseId);
    q.exec();
    QList<Forensic::Core::Investigator> list;
    while (q.next()) {
        Forensic::Core::Investigator inv;
        inv.id         = q.value("id").toString();
        inv.name       = q.value("name").toString();
        inv.email      = q.value("email").toString();
        inv.badge      = q.value("badge").toString();
        inv.role       = q.value("role").toString();
        inv.assignedAt = QDateTime::fromString(q.value("assigned_at").toString(), Qt::ISODate);
        list.append(inv);
    }
    return list;
}

// ─── Notes ────────────────────────────────────────────────────────────────────
bool CaseRepository::insertNote(const Forensic::Core::CaseNote &note) {
    QSqlQuery q(m_db);
    q.prepare(
        "INSERT OR REPLACE INTO notes(id,case_id,author_id,content,created_at,updated_at)"
        " VALUES(?,?,?,?,?,?)");
    q.addBindValue(note.id);
    q.addBindValue(note.caseId);
    q.addBindValue(note.authorId);
    q.addBindValue(note.content);
    q.addBindValue(note.createdAt.toString(Qt::ISODate));
    q.addBindValue(note.updatedAt.toString(Qt::ISODate));
    return q.exec();
}

bool CaseRepository::updateNote(const Forensic::Core::CaseNote &note) {
    QSqlQuery q(m_db);
    q.prepare("UPDATE notes SET content=?,updated_at=? WHERE id=?");
    q.addBindValue(note.content);
    q.addBindValue(note.updatedAt.toString(Qt::ISODate));
    q.addBindValue(note.id);
    return q.exec();
}

bool CaseRepository::removeNote(const QString &id) {
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM notes WHERE id=?");
    q.addBindValue(id);
    return q.exec();
}

QList<Forensic::Core::CaseNote> CaseRepository::notesForCase(const QString &caseId) const {
    QSqlQuery q(m_db);
    q.prepare("SELECT * FROM notes WHERE case_id=? ORDER BY created_at DESC");
    q.addBindValue(caseId);
    q.exec();
    QList<Forensic::Core::CaseNote> list;
    while (q.next()) {
        Forensic::Core::CaseNote n;
        n.id        = q.value("id").toString();
        n.caseId    = q.value("case_id").toString();
        n.authorId  = q.value("author_id").toString();
        n.content   = q.value("content").toString();
        n.createdAt = QDateTime::fromString(q.value("created_at").toString(), Qt::ISODate);
        n.updatedAt = QDateTime::fromString(q.value("updated_at").toString(), Qt::ISODate);
        list.append(n);
    }
    return list;
}

QString CaseRepository::lastError() const { return m_lastError; }

} // namespace Forensic::Services
