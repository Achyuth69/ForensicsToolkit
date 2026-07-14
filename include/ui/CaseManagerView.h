#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QTabWidget>
#include <QTextEdit>
#include <QLabel>
#include <QSplitter>
#include <memory>
#include "ForensicCase.h"
#include "CaseService.h"

namespace Forensic::UI {

class CaseManagerView : public QWidget {
    Q_OBJECT
public:
    explicit CaseManagerView(
        std::shared_ptr<Forensic::Services::CaseService> svc,
        QWidget *parent = nullptr);

    void refreshCaseList();
    void loadCase(const QString &caseId);

signals:
    void caseSelected(const Forensic::Core::ForensicCase &c);
    void evidenceSelected(const Forensic::Core::EvidenceItem &e);

private slots:
    void onNewCase();
    void onDeleteCase();
    void onAddEvidence();
    void onRemoveEvidence();
    void onAddInvestigator();
    void onAddNote();
    void onExportCase();
    void onCaseSelectionChanged();
    void onVerifyEvidence();

private:
    void setupUi();
    void setupCaseList();
    void setupDetailPanel();
    void setupEvidenceTab();
    void setupInvestigatorTab();
    void setupNotesTab();
    void setupTimelineTab();
    void populateCaseDetails(const Forensic::Core::ForensicCase &c);

    QSplitter    *m_splitter{nullptr};
    QTableWidget *m_caseTable{nullptr};
    QTabWidget   *m_detailTabs{nullptr};
    QTableWidget *m_evidenceTable{nullptr};
    QTableWidget *m_investigatorTable{nullptr};
    QTextEdit    *m_notesEdit{nullptr};
    QTreeWidget  *m_timelineTree{nullptr};

    std::shared_ptr<Forensic::Services::CaseService> m_svc;
    QString m_currentCaseId;
};

} // namespace Forensic::UI
