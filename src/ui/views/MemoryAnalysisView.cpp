#include "MemoryAnalysisView.h"
#include "MemoryAnalyzer.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QTableWidget>
#include <QTabWidget>
#include <QTextEdit>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QFont>
#include <QtConcurrent/QtConcurrent>

namespace Forensic::UI {

MemoryAnalysisView::MemoryAnalysisView(QWidget *parent) : QWidget(parent)
{
    auto *analyzer = new Forensic::Modules::MemoryAnalyzer(this);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // ── Header ────────────────────────────────────────────────────────────
    auto *header = new QWidget(this);
    header->setStyleSheet("background:#181825; border-bottom:1px solid #45475a;");
    auto *hl = new QHBoxLayout(header);
    hl->setContentsMargins(16, 10, 16, 10);
    auto *title = new QLabel("🧠  Memory Analysis", header);
    title->setStyleSheet("font-size:16px; font-weight:bold; color:#89b4fa;");
    hl->addWidget(title);
    layout->addWidget(header);

    // ── Toolbar ───────────────────────────────────────────────────────────
    auto *tb = new QWidget(this);
    tb->setStyleSheet("background:#262637; border-bottom:1px solid #45475a;");
    auto *tl = new QHBoxLayout(tb);
    tl->setContentsMargins(12, 8, 12, 8);

    auto *pathEdit   = new QLineEdit(tb);
    pathEdit->setPlaceholderText("Memory dump (.raw .vmem .dmp .mem .bin)...");
    auto *browseBtn  = new QPushButton("Browse...", tb);
    auto *analyzeBtn = new QPushButton("▶ Analyze", tb);
    auto *cancelBtn  = new QPushButton("■ Cancel", tb);
    analyzeBtn->setProperty("primary", true);

    tl->addWidget(pathEdit, 1);
    tl->addWidget(browseBtn);
    tl->addWidget(analyzeBtn);
    tl->addWidget(cancelBtn);
    layout->addWidget(tb);

    auto *progress = new QProgressBar(this);
    progress->setRange(0, 100); progress->setVisible(false); progress->setFixedHeight(6);
    layout->addWidget(progress);

    auto *statusLabel = new QLabel("Load a memory dump image to begin analysis", this);
    statusLabel->setStyleSheet("padding:4px 16px; color:#a6adc8; font-size:12px;");
    layout->addWidget(statusLabel);

    // ── Result tabs ───────────────────────────────────────────────────────
    auto *tabs = new QTabWidget(this);

    // Processes tab
    auto *procTable = new QTableWidget(0, 6);
    procTable->setHorizontalHeaderLabels({"PID","Name","PPID","Path","Status","Reason"});
    procTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    procTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    procTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    procTable->verticalHeader()->setVisible(false);
    procTable->setAlternatingRowColors(true);
    tabs->addTab(procTable, "Processes");

    // Strings tab
    auto *stringsEdit = new QTextEdit();
    stringsEdit->setReadOnly(true);
    stringsEdit->setFont(QFont("Consolas", 10));
    stringsEdit->setStyleSheet("background:#0d0d0d; color:#a6e3a1;");
    tabs->addTab(stringsEdit, "Strings");

    // Network connections tab
    auto *netTable = new QTableWidget(0, 6);
    netTable->setHorizontalHeaderLabels({"Protocol","Local IP","L.Port","Remote IP","R.Port","State"});
    netTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    netTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    netTable->verticalHeader()->setVisible(false);
    tabs->addTab(netTable, "Network Connections");

    // Suspicious tab
    auto *suspEdit = new QTextEdit();
    suspEdit->setReadOnly(true);
    suspEdit->setFont(QFont("Consolas", 11));
    tabs->addTab(suspEdit, "⚠ Suspicious Activity");

    layout->addWidget(tabs, 1);

    // ── Connections ───────────────────────────────────────────────────────
    connect(browseBtn, &QPushButton::clicked, this, [pathEdit, this] {
        QString f = QFileDialog::getOpenFileName(this, "Select Memory Image", "",
            "Memory Images (*.raw *.vmem *.dmp *.mem *.bin);;All Files (*)");
        if (!f.isEmpty()) pathEdit->setText(f);
    });

    connect(cancelBtn, &QPushButton::clicked, this, [analyzer, progress, statusLabel] {
        analyzer->cancel();
        progress->setVisible(false);
        statusLabel->setText("Cancelled");
    });

    connect(analyzeBtn, &QPushButton::clicked, this, [=] {
        QString path = pathEdit->text().trimmed();
        if (path.isEmpty()) {
            QMessageBox::warning(this, "No File", "Select a memory image file.");
            return;
        }
        progress->setVisible(true); progress->setValue(0);
        statusLabel->setText("Loading image...");
        procTable->setRowCount(0);
        stringsEdit->clear();
        netTable->setRowCount(0);
        suspEdit->clear();
        QtConcurrent::run([analyzer, path] { analyzer->analyzeImage(path); });
    });

    connect(analyzer, &Forensic::Modules::MemoryAnalyzer::progressChanged,
            this, [progress, statusLabel](int p, const QString &s) {
        progress->setValue(p);
        statusLabel->setText(s);
    }, Qt::QueuedConnection);

    connect(analyzer, &Forensic::Modules::MemoryAnalyzer::analysisComplete,
            this, [=](const Forensic::Modules::MemoryAnalysisResult &r) {
        progress->setVisible(false);
        statusLabel->setText(QString("✔ Analysis complete — %1 processes | %2 strings | %3 connections")
            .arg(r.processes.size()).arg(r.strings.size()).arg(r.networkConnections.size()));

        // Processes
        procTable->setRowCount(r.processes.size());
        for (int i = 0; i < r.processes.size(); i++) {
            const auto &p = r.processes[i];
            procTable->setItem(i, 0, new QTableWidgetItem(QString::number(p.pid)));
            procTable->setItem(i, 1, new QTableWidgetItem(p.name));
            procTable->setItem(i, 2, new QTableWidgetItem(QString::number(p.ppid)));
            procTable->setItem(i, 3, new QTableWidgetItem(p.path));
            auto *si = new QTableWidgetItem(p.isSuspicious ? "⚠ SUSPICIOUS" : "OK");
            if (p.isSuspicious) si->setForeground(QColor("#f38ba8"));
            else                 si->setForeground(QColor("#a6e3a1"));
            procTable->setItem(i, 4, si);
            procTable->setItem(i, 5, new QTableWidgetItem(p.suspicionReason));
        }
        tabs->setTabText(0, QString("Processes (%1)").arg(r.processes.size()));

        // Strings (cap at 5000)
        stringsEdit->clear();
        int limit = qMin(5000, r.strings.size());
        for (int i = 0; i < limit; i++) {
            stringsEdit->append(QString("0x%1  %2")
                .arg(r.strings[i].offset, 8, 16, QLatin1Char('0'))
                .arg(r.strings[i].value));
        }
        if (r.strings.size() > limit)
            stringsEdit->append(QString("\n... and %1 more strings").arg(r.strings.size() - limit));
        tabs->setTabText(1, QString("Strings (%1)").arg(r.strings.size()));

        // Network
        netTable->setRowCount(r.networkConnections.size());
        for (int i = 0; i < r.networkConnections.size(); i++) {
            const auto &c = r.networkConnections[i];
            netTable->setItem(i, 0, new QTableWidgetItem(c.protocol));
            netTable->setItem(i, 1, new QTableWidgetItem(c.localIp));
            netTable->setItem(i, 2, new QTableWidgetItem(QString::number(c.localPort)));
            netTable->setItem(i, 3, new QTableWidgetItem(c.remoteIp));
            netTable->setItem(i, 4, new QTableWidgetItem(QString::number(c.remotePort)));
            netTable->setItem(i, 5, new QTableWidgetItem(c.state));
        }
        tabs->setTabText(2, QString("Network (%1)").arg(r.networkConnections.size()));

        // Suspicious
        suspEdit->clear();
        if (r.suspiciousProcesses.isEmpty()) {
            suspEdit->setText("✓  No obviously suspicious processes detected.");
        } else {
            suspEdit->append(QString("⚠  %1 suspicious process(es) detected:\n")
                .arg(r.suspiciousProcesses.size()));
            for (const auto &p : r.suspiciousProcesses)
                suspEdit->append(QString("• PID %1  |  %2\n  → %3\n")
                    .arg(p.pid).arg(p.name, p.suspicionReason));
        }
        tabs->setTabText(3, QString("⚠ Suspicious (%1)").arg(r.suspiciousProcesses.size()));
    }, Qt::QueuedConnection);

    connect(analyzer, &Forensic::Modules::MemoryAnalyzer::errorOccurred,
            this, [progress, statusLabel, this](const QString &e) {
        progress->setVisible(false);
        statusLabel->setText("Error: " + e);
        QMessageBox::critical(this, "Analysis Error", e);
    }, Qt::QueuedConnection);
}

} // namespace Forensic::UI
