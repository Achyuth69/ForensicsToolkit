#include "CaseService.h"
#include "CaseRepository.h"
#include "Logger.h"
#include <QUuid>

namespace Forensic::Services {

CaseService::CaseService(QObject *parent) : QObject(parent) {}
CaseService::~CaseService() = default;

bool CaseService::openDatabase(const QString &dbPath) {
    m_repo = std::make_unique<CaseRepository>(dbPath);
    if (!m_repo->isOpen()) {
        emit databaseError("Failed to open database: " + m_repo->lastError());
        return false;
    }
    LOG_INFO("Database opened: " + dbPath);
    return true;
}

Forensic::Core::ForensicCase CaseService::createCase(const QString &title,
                                                       const QString &caseNumber,
                                                       const QString &description) {
    Forensic::Core::ForensicCase c;
    c.id          = QUuid::createUuid().toString(QUuid::WithoutBraces);
    c.title       = title;
    c.caseNumber  = caseNumber;
    c.description = description;
    c.status      = Forensic::Core::CaseStatus::Open;
    c.createdAt   = QDateTime::currentDateTime();
    c.updatedAt   = QDateTime::currentDateTime();

    if (m_repo && m_repo->insert(c)) {
        LOG_INFO("Case created: " + c.title + " [" + c.caseNumber + "]");
        emit caseCreated(c);
    } else {
        LOG_ERROR("Failed to insert case: " + (m_repo ? m_repo->lastError() : "no db"));
    }
    return c;
}

bool CaseService::updateCase(const Forensic::Core::ForensicCase &c) {
    if (!m_repo) return false;
    Forensic::Core::ForensicCase updated = c;
    updated.updatedAt = QDateTime::currentDateTime();
    bool ok = m_repo->update(updated);
    if (ok) emit caseUpdated(updated);
    return ok;
}

bool CaseService::deleteCase(const QString &caseId) {
    if (!m_repo) return false;
    bool ok = m_repo->remove(caseId);
    if (ok) emit caseDeleted(caseId);
    return ok;
}

std::optional<Forensic::Core::ForensicCase> CaseService::getCase(const QString &id) const {
    if (!m_repo) return std::nullopt;
    return m_repo->find(id);
}

QList<Forensic::Core::ForensicCase> CaseService::allCases() const {
    if (!m_repo) return {};
    return m_repo->findAll();
}

bool CaseService::addInvestigator(const QString &caseId,
                                   const Forensic::Core::Investigator &inv) {
    if (!m_repo) return false;
    Forensic::Core::Investigator i = inv;
    if (i.id.isEmpty())
        i.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    i.assignedAt = QDateTime::currentDateTime();
    return m_repo->insertInvestigator(caseId, i);
}

bool CaseService::removeInvestigator(const QString &, const QString &invId) {
    if (!m_repo) return false;
    return m_repo->removeInvestigator(invId);
}

bool CaseService::addEvidence(const QString &caseId,
                               const Forensic::Core::EvidenceItem &item) {
    if (!m_repo) return false;
    Forensic::Core::EvidenceItem e = item;
    if (e.id.isEmpty())
        e.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    e.caseId     = caseId;
    e.acquiredAt = QDateTime::currentDateTime();
    bool ok = m_repo->insertEvidence(e);
    if (ok) emit evidenceAdded(e);
    return ok;
}

bool CaseService::removeEvidence(const QString &, const QString &evidenceId) {
    if (!m_repo) return false;
    return m_repo->removeEvidence(evidenceId);
}

bool CaseService::verifyEvidence(const QString &, const QString &evidenceId) {
    if (!m_repo) return false;
    return m_repo->updateEvidenceVerified(evidenceId, true);
}

QList<Forensic::Core::EvidenceItem> CaseService::evidenceForCase(const QString &caseId) const {
    if (!m_repo) return {};
    return m_repo->evidenceForCase(caseId);
}

bool CaseService::addNote(const QString &caseId, const Forensic::Core::CaseNote &note) {
    if (!m_repo) return false;
    Forensic::Core::CaseNote n = note;
    if (n.id.isEmpty())
        n.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    n.caseId    = caseId;
    n.createdAt = QDateTime::currentDateTime();
    n.updatedAt = QDateTime::currentDateTime();
    return m_repo->insertNote(n);
}

bool CaseService::updateNote(const Forensic::Core::CaseNote &note) {
    if (!m_repo) return false;
    Forensic::Core::CaseNote n = note;
    n.updatedAt = QDateTime::currentDateTime();
    return m_repo->updateNote(n);
}

bool CaseService::deleteNote(const QString &noteId) {
    if (!m_repo) return false;
    return m_repo->removeNote(noteId);
}

} // namespace Forensic::Services
