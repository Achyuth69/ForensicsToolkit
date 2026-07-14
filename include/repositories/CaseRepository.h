#pragma once
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QList>
#include <optional>
#include "ForensicCase.h"

namespace Forensic::Services {

class CaseRepository {
public:
    explicit CaseRepository(const QString &dbPath);
    ~CaseRepository();

    bool isOpen() const;
    bool initSchema();

    // Cases
    bool insert(const Forensic::Core::ForensicCase &c);
    bool update(const Forensic::Core::ForensicCase &c);
    bool remove(const QString &id);
    std::optional<Forensic::Core::ForensicCase> find(const QString &id) const;
    QList<Forensic::Core::ForensicCase> findAll() const;

    // Evidence
    bool insertEvidence(const Forensic::Core::EvidenceItem &e);
    bool removeEvidence(const QString &id);
    bool updateEvidenceVerified(const QString &id, bool verified);
    QList<Forensic::Core::EvidenceItem> evidenceForCase(const QString &caseId) const;

    // Investigators
    bool insertInvestigator(const QString &caseId,
                            const Forensic::Core::Investigator &inv);
    bool removeInvestigator(const QString &id);
    QList<Forensic::Core::Investigator> investigatorsForCase(const QString &caseId) const;

    // Notes
    bool insertNote(const Forensic::Core::CaseNote &note);
    bool updateNote(const Forensic::Core::CaseNote &note);
    bool removeNote(const QString &id);
    QList<Forensic::Core::CaseNote> notesForCase(const QString &caseId) const;

    QString lastError() const;

private:
    QSqlDatabase m_db;
    QString      m_lastError;

    bool execQuery(const QString &sql, const QVariantList &bindings = {});
    Forensic::Core::ForensicCase rowToCase(const QSqlQuery &q) const;
};

} // namespace Forensic::Services
