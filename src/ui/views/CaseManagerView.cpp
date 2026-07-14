#include "CaseManagerView.h"
#include "NewCaseDialog.h"
#include "AddEvidenceDialog.h"
#include "AddInvestigatorDialog.h"
#include "HashEngine.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QPushButton>
#include <QLabel>
#include <QSplitter>
#include <QMessageBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QDateTime>
#include <QJsonDocument>
#include <QUuid>

namespace Forensic::UI {

CaseManagerView::CaseManagerView(
    std::shared_ptr<Forensic::Services::CaseService> svc,
    QWidget *parent)
    : QWidget(parent), m_svc(svc)
{
    setupUi();
    refreshCaseList();

    connect(m_svc.get(), &Forensic::Services::CaseService::caseCreated,
            this, [this](auto&){ refreshCaseList(); });
}

void CaseManagerView::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // Header bar
    auto *header = new QWidget(this);
    header->setObjectName("PanelHeader");
    header->setStyleSheet("#PanelHeader { background: #181825; border-bottom: 1px solid #45475a; }");
    auto *hLayout = new QHBoxLayout(header);
    hLayout->setContentsMargins(16, 10, 16, 10);

    auto *title = new QLabel("📂  Case Management", header);
    title->setStyleSheet("font-size: 16px; font-weight: bold; color: #89b4fa;");

    auto *newBtn    = new QPushButton("+ New Case", header);
    auto *deleteBtn = new QPushButton("Delete", header);
    auto *exportBtn = new QPushButton("Export JSON", header);
    newBtn->setProperty("primary", true);

    connect(newBtn,    &QPushButton::clicked, this, &CaseManagerView::onNewCase);
    connect(deleteBtn, &QPushButton::clicked, this, &CaseManagerView::onDeleteCase);
    connect(exportBtn, &QPushButton::clicked, this, &CaseManagerView::onExportCase);

    hLayout->addWidget(title, 1);
    hLayout->addWidget(newBtn);
    hLayout->addWidget(exportBtn);
    hLayout->addWidget(deleteBtn);

    mainLayout->addWidget(header);

    m_splitter = new QSplitter(Qt::Horizontal, this);
    setupCaseList();
    setupDetailPanel();
    m_splitter->addWidget(m_caseTable);
    m_splitter->addWidget(m_detailTabs);
    m_splitter->setSizes({380, 820});
    m_splitter->setStretchFactor(1, 1);

    mainLayout->addWidget(m_splitter, 1);
}

void CaseManagerView::setupCaseList() {
    m_caseTable = new QTableWidget(0, 5, this);
    m_caseTable->setHorizontalHeaderLabels({"Case #", "Title", "Status", "Evidence", "Created"});
    m_caseTable->horizontalHeader()->setStretchLastSection(true);
    m_caseTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_caseTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_caseTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_caseTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_caseTable->verticalHeader()->setVisible(false);
    m_caseTable->setAlternatingRowColors(true);

    connect(m_caseTable, &QTableWidget::itemSelectionChanged,
            this, &CaseManagerView::onCaseSelectionChanged);
}

void CaseManagerView::setupDetailPanel() {
    m_detailTabs = new QTabWidget(this);
    setupEvidenceTab();
    setupInvestigatorTab();
    setupNotesTab();
    setupTimelineTab();
}

void CaseManagerView::setupEvidenceTab() {
    auto *tab = new QWidget(m_detailTabs);
    auto *layout = new QVBoxLayout(tab);

    auto *toolbar = new QHBoxLayout();
    auto *addBtn  = new QPushButton("+ Add Evidence", tab);
    auto *rmBtn   = new QPushButton("Remove", tab);
    auto *verBtn  = new QPushButton("Verify Hash", tab);
    addBtn->setProperty("primary", true);
    connect(addBtn, &QPushButton::clicked, this, &CaseManagerView::onAddEvidence);
    connect(rmBtn,  &QPushButton::clicked, this, &CaseManagerView::onRemoveEvidence);
    connect(verBtn, &QPushButton::clicked, this, &CaseManagerView::onVerifyEvidence);
    toolbar->addWidget(addBtn);
    toolbar->addWidget(verBtn);
    toolbar->addStretch();
    toolbar->addWidget(rmBtn);

    m_evidenceTable = new QTableWidget(0, 6, tab);
    m_evidenceTable->setHorizontalHeaderLabels(
        {"Label", "Type", "Size", "SHA-256", "Acquired", "Verified"});
    m_evidenceTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_evidenceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_evidenceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_evidenceTable->verticalHeader()->setVisible(false);

    layout->addLayout(toolbar);
    layout->addWidget(m_evidenceTable, 1);
    m_detailTabs->addTab(tab, "Evidence");
}

void CaseManagerView::setupInvestigatorTab() {
    auto *tab = new QWidget(m_detailTabs);
    auto *layout = new QVBoxLayout(tab);

    auto *toolbar = new QHBoxLayout();
    auto *addBtn  = new QPushButton("+ Add Investigator", tab);
    addBtn->setProperty("primary", true);
    connect(addBtn, &QPushButton::clicked, this, &CaseManagerView::onAddInvestigator);
    toolbar->addWidget(addBtn);
    toolbar->addStretch();

    m_investigatorTable = new QTableWidget(0, 4, tab);
    m_investigatorTable->setHorizontalHeaderLabels({"Name", "Badge", "Role", "Email"});
    m_investigatorTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_investigatorTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_investigatorTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_investigatorTable->verticalHeader()->setVisible(false);

    layout->addLayout(toolbar);
    layout->addWidget(m_investigatorTable, 1);
    m_detailTabs->addTab(tab, "Investigators");
}

void CaseManagerView::setupNotesTab() {
    auto *tab = new QWidget(m_detailTabs);
    auto *layout = new QVBoxLayout(tab);

    auto *toolbar = new QHBoxLayout();
    auto *addBtn  = new QPushButton("+ Add Note", tab);
    addBtn->setProperty("primary", true);
    connect(addBtn, &QPushButton::clicked, this, &CaseManagerView::onAddNote);
    toolbar->addWidget(addBtn);
    toolbar->addStretch();

    m_notesEdit = new QTextEdit(tab);
    m_notesEdit->setReadOnly(true);
    m_notesEdit->setPlaceholderText("Select a case to view notes...");

    layout->addLayout(toolbar);
    layout->addWidget(m_notesEdit, 1);
    m_detailTabs->addTab(tab, "Notes");
}

void CaseManagerView::setupTimelineTab() {
    auto *tab = new QWidget(m_detailTabs);
    auto *layout = new QVBoxLayout(tab);

    m_timelineTree = new QTreeWidget(tab);
    m_timelineTree->setHeaderLabels({"Time", "Event", "Details"});
    m_timelineTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    layout->addWidget(m_timelineTree);
    m_detailTabs->addTab(tab, "Timeline");
}

void CaseManagerView::refreshCaseList() {
    m_caseTable->setRowCount(0);
    auto cases = m_svc->allCases();
    m_caseTable->setRowCount(cases.size());

    for (int i = 0; i < cases.size(); i++) {
        const auto &c = cases[i];
        m_caseTable->setItem(i, 0, new QTableWidgetItem(c.caseNumber));
        m_caseTable->setItem(i, 1, new QTableWidgetItem(c.title));
        m_caseTable->setItem(i, 2, new QTableWidgetItem(c.statusString()));
        m_caseTable->setItem(i, 3, new QTableWidgetItem(QString::number(c.evidence.size())));
        m_caseTable->setItem(i, 4, new QTableWidgetItem(c.createdAt.toString("yyyy-MM-dd")));
        m_caseTable->item(i, 0)->setData(Qt::UserRole, c.id);
    }
}

void CaseManagerView::onCaseSelectionChanged() {
    auto sel = m_caseTable->selectedItems();
    if (sel.isEmpty()) return;
    int row = m_caseTable->currentRow();
    QString id = m_caseTable->item(row, 0)->data(Qt::UserRole).toString();
    m_currentCaseId = id;
    loadCase(id);
}

void CaseManagerView::loadCase(const QString &caseId) {
    auto opt = m_svc->getCase(caseId);
    if (!opt) return;
    const auto &c = *opt;

    // Evidence
    m_evidenceTable->setRowCount(0);
    for (int i = 0; i < c.evidence.size(); i++) {
        const auto &ev = c.evidence[i];
        m_evidenceTable->insertRow(i);
        m_evidenceTable->setItem(i, 0, new QTableWidgetItem(ev.label));
        m_evidenceTable->setItem(i, 1, new QTableWidgetItem(ev.type));
        m_evidenceTable->setItem(i, 2, new QTableWidgetItem(
            QString::number(ev.sizeBytes / 1024) + " KB"));
        m_evidenceTable->setItem(i, 3, new QTableWidgetItem(ev.hash.left(20) + "..."));
        m_evidenceTable->setItem(i, 4, new QTableWidgetItem(
            ev.acquiredAt.toString("yyyy-MM-dd")));
        m_evidenceTable->setItem(i, 5, new QTableWidgetItem(
            ev.verified ? "✓ Verified" : "Unverified"));
        m_evidenceTable->item(i, 0)->setData(Qt::UserRole, ev.id);
    }

    // Investigators
    m_investigatorTable->setRowCount(0);
    for (int i = 0; i < c.investigators.size(); i++) {
        const auto &inv = c.investigators[i];
        m_investigatorTable->insertRow(i);
        m_investigatorTable->setItem(i, 0, new QTableWidgetItem(inv.name));
        m_investigatorTable->setItem(i, 1, new QTableWidgetItem(inv.badge));
        m_investigatorTable->setItem(i, 2, new QTableWidgetItem(inv.role));
        m_investigatorTable->setItem(i, 3, new QTableWidgetItem(inv.email));
    }

    // Notes
    m_notesEdit->clear();
    for (const auto &note : c.notes) {
        m_notesEdit->append(QString("[%1] %2\n%3\n")
            .arg(note.createdAt.toString("yyyy-MM-dd hh:mm"),
                 note.authorId, note.content));
    }

    // Timeline — combine evidence acquisition events
    m_timelineTree->clear();
    for (const auto &ev : c.evidence) {
        auto *item = new QTreeWidgetItem(m_timelineTree);
        item->setText(0, ev.acquiredAt.toString("yyyy-MM-dd hh:mm"));
        item->setText(1, "Evidence Acquired");
        item->setText(2, ev.label + " (" + ev.type + ")");
    }

    emit caseSelected(c);
}

void CaseManagerView::onNewCase() {
    NewCaseDialog dlg(m_svc, this);
    if (dlg.exec() == QDialog::Accepted) refreshCaseList();
}

void CaseManagerView::onDeleteCase() {
    if (m_currentCaseId.isEmpty()) return;
    auto r = QMessageBox::question(this, "Delete Case",
        "Permanently delete this case and all its data?",
        QMessageBox::Yes | QMessageBox::No);
    if (r == QMessageBox::Yes) {
        m_svc->deleteCase(m_currentCaseId);
        m_currentCaseId.clear();
        refreshCaseList();
    }
}

void CaseManagerView::onAddEvidence() {
    if (m_currentCaseId.isEmpty()) {
        QMessageBox::warning(this, "No Case", "Please select a case first.");
        return;
    }
    AddEvidenceDialog dlg(m_svc, m_currentCaseId, this);
    if (dlg.exec() == QDialog::Accepted) loadCase(m_currentCaseId);
}

void CaseManagerView::onRemoveEvidence() {
    auto sel = m_evidenceTable->selectedItems();
    if (sel.isEmpty()) return;
    int row = m_evidenceTable->currentRow();
    QString evId = m_evidenceTable->item(row, 0)->data(Qt::UserRole).toString();
    m_svc->removeEvidence(m_currentCaseId, evId);
    loadCase(m_currentCaseId);
}

void CaseManagerView::onVerifyEvidence() {
    auto sel = m_evidenceTable->selectedItems();
    if (sel.isEmpty()) return;
    int row = m_evidenceTable->currentRow();
    QString evId = m_evidenceTable->item(row, 0)->data(Qt::UserRole).toString();
    m_svc->verifyEvidence(m_currentCaseId, evId);
    loadCase(m_currentCaseId);
}

void CaseManagerView::onAddInvestigator() {
    if (m_currentCaseId.isEmpty()) {
        QMessageBox::warning(this, "No Case", "Please select a case first.");
        return;
    }
    AddInvestigatorDialog dlg(m_svc, m_currentCaseId, this);
    if (dlg.exec() == QDialog::Accepted) loadCase(m_currentCaseId);
}

void CaseManagerView::onAddNote() {
    if (m_currentCaseId.isEmpty()) return;
    // Simple inline note
    Forensic::Core::CaseNote note;
    note.authorId = "Current User";
    note.content  = "New note added at " + QDateTime::currentDateTime().toString();
    m_svc->addNote(m_currentCaseId, note);
    loadCase(m_currentCaseId);
}

void CaseManagerView::onExportCase() {
    if (m_currentCaseId.isEmpty()) return;
    auto opt = m_svc->getCase(m_currentCaseId);
    if (!opt) return;
    QString path = QFileDialog::getSaveFileName(this, "Export Case", "", "JSON (*.json)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (f.open(QIODevice::WriteOnly))
        f.write(QJsonDocument(opt->toJson()).toJson(QJsonDocument::Indented));
}

} // namespace Forensic::UI
