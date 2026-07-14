#pragma once
#include <QObject>
#include <QList>
#include <optional>
#include <memory>
#include "ForensicCase.h"

namespace Forensic::Services {

class CaseRepository;

class CaseService : public QObject {
    Q_OBJECT
public:
    explicit CaseService(QObject *parent = nullptr);
    ~CaseService() override;

    bool openDatabase(const QString &dbPath);

    // Case CRUD
    Forensic::Core::ForensicCase createCase(const QString &title,
                                             const QString &caseNumber,
                                             const QString &description);
    bool updateCase(const Forensic::Core::ForensicCase &c);
    bool deleteCase(const QString &caseId);
    std::optional<Forensic::Core::ForensicCase> getCase(const QString &id) const;
    QList<Forensic::Core::ForensicCase> allCases() const;

    // Investigator management
    bool addInvestigator(const QString &caseId,
                         const Forensic::Core::Investigator &inv);
    bool removeInvestigator(const QString &caseId, const QString &invId);

    // Evidence management
    bool addEvidence(const QString &caseId,
                     const Forensic::Core::EvidenceItem &item);
    bool removeEvidence(const QString &caseId, const QString &evidenceId);
    bool verifyEvidence(const QString &caseId, const QString &evidenceId);
    QList<Forensic::Core::EvidenceItem> evidenceForCase(const QString &caseId) const;

    // Notes
    bool addNote(const QString &caseId, const Forensic::Core::CaseNote &note);
    bool updateNote(const Forensic::Core::CaseNote &note);
    bool deleteNote(const QString &noteId);

signals:
    void caseCreated(const Forensic::Core::ForensicCase &c);
    void caseUpdated(const Forensic::Core::ForensicCase &c);
    void caseDeleted(const QString &id);
    void evidenceAdded(const Forensic::Core::EvidenceItem &e);
    void databaseError(const QString &error);

private:
    std::unique_ptr<CaseRepository> m_repo;
};

} // namespace Forensic::Services
