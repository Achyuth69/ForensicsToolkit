#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QSplitter>
#include <QLineEdit>
#include <QProgressBar>
#include <QLabel>
#include <QTabWidget>
#include <memory>
#include "FileSystemAnalyzer.h"

namespace Forensic::UI {

class FileSystemView : public QWidget {
    Q_OBJECT
public:
    explicit FileSystemView(QWidget *parent = nullptr);

signals:
    void scanStarted(const QString &path);
    void scanFinished();

private slots:
    void onBrowse();
    void onStartScan();
    void onCancelScan();
    void onScanProgress(int pct, const QString &current);
    void onScanComplete(const Forensic::Modules::ScanSummary &summary);
    void onFileFound(const Forensic::Modules::FileEntry &entry);
    void onFilterChanged(const QString &text);
    void onExportResults();
    void onTableItemDoubleClicked(int row, int col);

private:
    void setupUi();
    void setupToolbar();
    void setupFiltersBar();
    void setupResultsTable();
    void setupSummaryPanel();
    void addFileRow(const Forensic::Modules::FileEntry &entry);
    void updateSummary(const Forensic::Modules::ScanSummary &s);

    QLineEdit    *m_pathEdit{nullptr};
    QProgressBar *m_progress{nullptr};
    QLabel       *m_statusLabel{nullptr};
    QTabWidget   *m_tabs{nullptr};
    QTableWidget *m_allTable{nullptr};
    QTableWidget *m_hiddenTable{nullptr};
    QTableWidget *m_dupTable{nullptr};

    std::unique_ptr<Forensic::Modules::FileSystemAnalyzer> m_analyzer;
    bool m_scanning{false};
};

} // namespace Forensic::UI
