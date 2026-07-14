#include "FileSystemView.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QCheckBox>
#include <QGroupBox>
#include <QJsonDocument>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDirIterator>
#include <QtConcurrent/QtConcurrent>

namespace Forensic::UI {

FileSystemView::FileSystemView(QWidget *parent) : QWidget(parent) {
    m_analyzer = std::make_unique<Forensic::Modules::FileSystemAnalyzer>(this);

    connect(m_analyzer.get(), &Forensic::Modules::FileSystemAnalyzer::progressChanged,
            this, &FileSystemView::onScanProgress);
    connect(m_analyzer.get(), &Forensic::Modules::FileSystemAnalyzer::scanComplete,
            this, &FileSystemView::onScanComplete);
    connect(m_analyzer.get(), &Forensic::Modules::FileSystemAnalyzer::fileFound,
            this, &FileSystemView::onFileFound);
    connect(m_analyzer.get(), &Forensic::Modules::FileSystemAnalyzer::errorOccurred,
            this, [this](const QString &e){
                QMessageBox::critical(this, "Scan Error", e);
                m_scanning = false;
            });

    setupUi();
}

void FileSystemView::setupUi() {
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // Header
    auto *header = new QWidget(this);
    header->setStyleSheet("background: #181825; border-bottom: 1px solid #45475a;");
    auto *hl = new QHBoxLayout(header);
    hl->setContentsMargins(16, 10, 16, 10);
    auto *title = new QLabel("🗂  File System Analyzer", header);
    title->setStyleSheet("font-size: 16px; font-weight: bold; color: #89b4fa;");
    hl->addWidget(title);
    layout->addWidget(header);

    setupToolbar();
    setupFiltersBar();
    setupResultsTable();
    setupSummaryPanel();
}

void FileSystemView::setupToolbar() {
    auto *tb = new QWidget(this);
    tb->setStyleSheet("background: #262637; border-bottom: 1px solid #45475a;");
    auto *tl = new QHBoxLayout(tb);
    tl->setContentsMargins(12, 8, 12, 8);
    tl->setSpacing(8);

    auto *pathLabel = new QLabel("Path:", tb);
    m_pathEdit = new QLineEdit(tb);
    m_pathEdit->setPlaceholderText("Select or type a directory path...");

    auto *browseBtn = new QPushButton("Browse...", tb);
    auto *scanBtn   = new QPushButton("▶ Start Scan", tb);
    auto *cancelBtn = new QPushButton("■ Cancel", tb);
    auto *exportBtn = new QPushButton("Export JSON", tb);
    scanBtn->setProperty("primary", true);

    connect(browseBtn, &QPushButton::clicked, this, &FileSystemView::onBrowse);
    connect(scanBtn,   &QPushButton::clicked, this, &FileSystemView::onStartScan);
    connect(cancelBtn, &QPushButton::clicked, this, &FileSystemView::onCancelScan);
    connect(exportBtn, &QPushButton::clicked, this, &FileSystemView::onExportResults);

    tl->addWidget(pathLabel);
    tl->addWidget(m_pathEdit, 1);
    tl->addWidget(browseBtn);
    tl->addWidget(scanBtn);
    tl->addWidget(cancelBtn);
    tl->addStretch();
    tl->addWidget(exportBtn);

    static_cast<QVBoxLayout*>(layout())->addWidget(tb);

    m_progress = new QProgressBar(this);
    m_progress->setRange(0, 100);
    m_progress->setVisible(false);
    m_progress->setFixedHeight(6);
    static_cast<QVBoxLayout*>(layout())->addWidget(m_progress);

    m_statusLabel = new QLabel("Ready", this);
    m_statusLabel->setStyleSheet("padding: 4px 16px; color: #a6adc8; font-size: 12px;");
    static_cast<QVBoxLayout*>(layout())->addWidget(m_statusLabel);
}

void FileSystemView::setupFiltersBar() {
    // Search filter
    auto *filterBar = new QWidget(this);
    auto *fl = new QHBoxLayout(filterBar);
    fl->setContentsMargins(12, 4, 12, 4);

    auto *searchLabel = new QLabel("🔍 Filter:", filterBar);
    auto *searchEdit  = new QLineEdit(filterBar);
    searchEdit->setPlaceholderText("Filter by name, extension, path...");
    searchEdit->setFixedWidth(300);
    connect(searchEdit, &QLineEdit::textChanged, this, &FileSystemView::onFilterChanged);

    fl->addWidget(searchLabel);
    fl->addWidget(searchEdit);
    fl->addStretch();

    static_cast<QVBoxLayout*>(layout())->addWidget(filterBar);
}

void FileSystemView::setupResultsTable() {
    m_tabs = new QTabWidget(this);

    // All files tab
    auto *allTab = new QWidget(m_tabs);
    auto *al = new QVBoxLayout(allTab);
    al->setContentsMargins(0, 0, 0, 0);
    m_allTable = new QTableWidget(0, 7, allTab);
    m_allTable->setHorizontalHeaderLabels(
        {"Name", "Path", "Size", "Type", "Modified", "SHA-256", "Flags"});
    m_allTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_allTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_allTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_allTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_allTable->verticalHeader()->setVisible(false);
    m_allTable->setAlternatingRowColors(true);
    m_allTable->setSortingEnabled(true);
    connect(m_allTable, &QTableWidget::cellDoubleClicked,
            this, &FileSystemView::onTableItemDoubleClicked);
    al->addWidget(m_allTable);
    m_tabs->addTab(allTab, "All Files");

    // Hidden/System files tab
    auto *hidTab = new QWidget(m_tabs);
    auto *hl2 = new QVBoxLayout(hidTab);
    hl2->setContentsMargins(0, 0, 0, 0);
    m_hiddenTable = new QTableWidget(0, 5, hidTab);
    m_hiddenTable->setHorizontalHeaderLabels({"Name", "Path", "Size", "Modified", "Reason"});
    m_hiddenTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_hiddenTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_hiddenTable->verticalHeader()->setVisible(false);
    hl2->addWidget(m_hiddenTable);
    m_tabs->addTab(hidTab, "Hidden / System");

    // Duplicates tab
    auto *dupTab = new QWidget(m_tabs);
    auto *dl = new QVBoxLayout(dupTab);
    dl->setContentsMargins(0, 0, 0, 0);
    m_dupTable = new QTableWidget(0, 4, dupTab);
    m_dupTable->setHorizontalHeaderLabels({"Name", "Path", "Size", "SHA-256"});
    m_dupTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_dupTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_dupTable->verticalHeader()->setVisible(false);
    dl->addWidget(m_dupTable);
    m_tabs->addTab(dupTab, "Duplicates");

    static_cast<QVBoxLayout*>(layout())->addWidget(m_tabs, 1);
}

void FileSystemView::setupSummaryPanel() {
    // Summary shown in the status label
}

void FileSystemView::onBrowse() {
    QString path = QFileDialog::getExistingDirectory(
        this, "Select Directory to Scan", QDir::homePath());
    if (!path.isEmpty()) m_pathEdit->setText(path);
}

void FileSystemView::onStartScan() {
    if (m_scanning) return;
    QString path = m_pathEdit->text().trimmed();
    if (path.isEmpty()) {
        QMessageBox::warning(this, "No Path", "Please select a directory to scan.");
        return;
    }
    m_scanning = true;
    m_allTable->setRowCount(0);
    m_hiddenTable->setRowCount(0);
    m_dupTable->setRowCount(0);
    m_progress->setVisible(true);
    m_progress->setValue(0);
    m_statusLabel->setText("Scanning " + path + "...");
    emit scanStarted(path);

    // Run in background thread
    QtConcurrent::run([this, path]() {
        m_analyzer->scanDirectory(path, true, true);
    });
}

void FileSystemView::onCancelScan() {
    m_analyzer->cancel();
    m_scanning = false;
    m_progress->setVisible(false);
    m_statusLabel->setText("Scan cancelled");
}

void FileSystemView::onScanProgress(int pct, const QString &current) {
    m_progress->setValue(pct);
    m_statusLabel->setText(current.left(100));
}

void FileSystemView::onScanComplete(const Forensic::Modules::ScanSummary &s) {
    m_scanning = false;
    m_progress->setVisible(false);
    updateSummary(s);
    emit scanFinished();

    // Populate duplicates
    auto dups = m_analyzer->duplicates();
    m_dupTable->setRowCount(dups.size());
    for (int i = 0; i < dups.size(); i++) {
        const auto &e = dups[i];
        m_dupTable->setItem(i, 0, new QTableWidgetItem(e.name));
        m_dupTable->setItem(i, 1, new QTableWidgetItem(e.path));
        m_dupTable->setItem(i, 2, new QTableWidgetItem(
            QString::number(e.size / 1024) + " KB"));
        m_dupTable->setItem(i, 3, new QTableWidgetItem(e.sha256));
    }
    m_tabs->setTabText(2, QString("Duplicates (%1)").arg(dups.size()));
}

void FileSystemView::onFileFound(const Forensic::Modules::FileEntry &entry) {
    addFileRow(entry);
    if (entry.isHidden || entry.isSystem) {
        int r = m_hiddenTable->rowCount();
        m_hiddenTable->insertRow(r);
        m_hiddenTable->setItem(r, 0, new QTableWidgetItem(entry.name));
        m_hiddenTable->setItem(r, 1, new QTableWidgetItem(entry.path));
        m_hiddenTable->setItem(r, 2, new QTableWidgetItem(
            QString::number(entry.size / 1024) + " KB"));
        m_hiddenTable->setItem(r, 3, new QTableWidgetItem(
            entry.modified.toString("yyyy-MM-dd hh:mm")));
        m_hiddenTable->setItem(r, 4, new QTableWidgetItem(
            entry.isSystem ? "System" : "Hidden"));
    }
}

void FileSystemView::addFileRow(const Forensic::Modules::FileEntry &entry) {
    int r = m_allTable->rowCount();
    m_allTable->insertRow(r);
    m_allTable->setItem(r, 0, new QTableWidgetItem(entry.name));
    m_allTable->setItem(r, 1, new QTableWidgetItem(entry.path));
    m_allTable->setItem(r, 2, new QTableWidgetItem(
        QString::number(entry.size / 1024) + " KB"));
    m_allTable->setItem(r, 3, new QTableWidgetItem(entry.mimeType));
    m_allTable->setItem(r, 4, new QTableWidgetItem(
        entry.modified.toString("yyyy-MM-dd hh:mm")));
    m_allTable->setItem(r, 5, new QTableWidgetItem(entry.sha256.left(16) + "..."));
    QStringList flags;
    if (entry.isHidden)  flags << "H";
    if (entry.isSystem)  flags << "S";
    if (entry.isSymlink) flags << "L";
    m_allTable->setItem(r, 6, new QTableWidgetItem(flags.join("")));
}

void FileSystemView::updateSummary(const Forensic::Modules::ScanSummary &s) {
    m_statusLabel->setText(
        QString("✔ Scan complete — Files: %1 | Dirs: %2 | Hidden: %3 | "
                "Duplicates: %4 | Size: %5 MB")
        .arg(s.totalFiles).arg(s.totalDirs).arg(s.hiddenFiles)
        .arg(s.duplicates)
        .arg(s.totalSize / 1024 / 1024));
    m_tabs->setTabText(0, QString("All Files (%1)").arg(s.totalFiles));
    m_tabs->setTabText(1, QString("Hidden / System (%1)").arg(s.hiddenFiles));
}

void FileSystemView::onFilterChanged(const QString &text) {
    for (int r = 0; r < m_allTable->rowCount(); r++) {
        bool match = text.isEmpty();
        if (!match) {
            for (int c = 0; c < m_allTable->columnCount() && !match; c++) {
                auto *item = m_allTable->item(r, c);
                if (item && item->text().contains(text, Qt::CaseInsensitive))
                    match = true;
            }
        }
        m_allTable->setRowHidden(r, !match);
    }
}

void FileSystemView::onExportResults() {
    QString path = QFileDialog::getSaveFileName(this, "Export Results", "", "JSON (*.json)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (f.open(QIODevice::WriteOnly))
        f.write(QJsonDocument(m_analyzer->toJson()).toJson(QJsonDocument::Indented));
}

void FileSystemView::onTableItemDoubleClicked(int row, int) {
    auto *item = m_allTable->item(row, 1);
    if (item) QMessageBox::information(this, "File Path", item->text());
}

} // namespace Forensic::UI
