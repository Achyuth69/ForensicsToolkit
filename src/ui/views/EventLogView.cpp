#include "EventLogView.h"
#include "EventLogParser.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QTableWidget>
#include <QTabWidget>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QtConcurrent/QtConcurrent>

namespace Forensic::UI {

EventLogView::EventLogView(QWidget *parent) : QWidget(parent)
{
    auto *parser = new Forensic::Modules::EventLogParser(this);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // ── Header ────────────────────────────────────────────────────────────
    auto *header = new QWidget(this);
    header->setStyleSheet("background:#181825; border-bottom:1px solid #45475a;");
    auto *hl = new QHBoxLayout(header);
    hl->setContentsMargins(16, 10, 16, 10);
    auto *title = new QLabel("📋  Windows Event Log Parser", header);
    title->setStyleSheet("font-size:16px; font-weight:bold; color:#89b4fa;");
    hl->addWidget(title);
    layout->addWidget(header);

    // ── Toolbar ───────────────────────────────────────────────────────────
    auto *tb = new QWidget(this);
    tb->setStyleSheet("background:#262637; border-bottom:1px solid #45475a;");
    auto *tl = new QHBoxLayout(tb);
    tl->setContentsMargins(12, 8, 12, 8);

    auto *pathEdit  = new QLineEdit(tb);
    pathEdit->setPlaceholderText("Event log file (.evtx or exported .xml)...");
    auto *browseBtn = new QPushButton("Browse...", tb);
    auto *parseBtn  = new QPushButton("▶ Parse Log", tb);
    parseBtn->setProperty("primary", true);

    tl->addWidget(pathEdit, 1);
    tl->addWidget(browseBtn);
    tl->addWidget(parseBtn);
    layout->addWidget(tb);

    auto *progress = new QProgressBar(this);
    progress->setRange(0, 100); progress->setVisible(false); progress->setFixedHeight(6);
    layout->addWidget(progress);

    auto *statusLabel = new QLabel("Load an event log file to begin analysis", this);
    statusLabel->setStyleSheet("padding:4px 16px; color:#a6adc8; font-size:12px;");
    layout->addWidget(statusLabel);

    // ── Tabs ──────────────────────────────────────────────────────────────
    auto *tabs = new QTabWidget(this);

    // Summary tab
    auto *sumTab = new QWidget(tabs);
    auto *sl = new QVBoxLayout(sumTab);
    sl->setContentsMargins(12, 12, 12, 12);
    auto *sumTable = new QTableWidget(0, 2, sumTab);
    sumTable->setObjectName("summaryTable");
    sumTable->setHorizontalHeaderLabels({"Category", "Count"});
    sumTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    sumTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    sumTable->verticalHeader()->setVisible(false);
    sl->addWidget(sumTable);
    tabs->addTab(sumTab, "Summary");

    // All events tab
    auto makeEventsTable = [](QWidget *parent) {
        auto *t = new QTableWidget(0, 7, parent);
        t->setHorizontalHeaderLabels({"Time","Event ID","Source","User","Computer","Category","Message"});
        t->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
        t->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        t->setEditTriggers(QAbstractItemView::NoEditTriggers);
        t->verticalHeader()->setVisible(false);
        t->setAlternatingRowColors(true);
        t->setSelectionBehavior(QAbstractItemView::SelectRows);
        return t;
    };

    auto *allTable     = makeEventsTable(tabs);
    auto *flaggedTable = makeEventsTable(tabs);
    tabs->addTab(allTable,     "All Events");
    tabs->addTab(flaggedTable, "Flagged");

    layout->addWidget(tabs, 1);

    // ── Populate helper ───────────────────────────────────────────────────
    auto populateTable = [](QTableWidget *t,
                             const QList<Forensic::Modules::EventLogEntry> &entries,
                             int limit = 50000)
    {
        int n = qMin(limit, entries.size());
        t->setRowCount(n);
        for (int i = 0; i < n; i++) {
            const auto &e = entries[i];
            t->setItem(i, 0, new QTableWidgetItem(e.timestamp.toString("yyyy-MM-dd hh:mm:ss")));
            t->setItem(i, 1, new QTableWidgetItem(QString::number(e.eventId)));
            t->setItem(i, 2, new QTableWidgetItem(e.source));
            t->setItem(i, 3, new QTableWidgetItem(e.user));
            t->setItem(i, 4, new QTableWidgetItem(e.computer));
            QString cat;
            using EC = Forensic::Modules::EventCategory;
            switch (e.category) {
            case EC::FailedLogin:      cat = "Failed Login";     break;
            case EC::SuccessfulLogin:  cat = "Successful Login"; break;
            case EC::UsbInsertion:     cat = "USB Inserted";     break;
            case EC::ProcessExecution: cat = "Process Exec";     break;
            case EC::ApplicationCrash: cat = "App Crash";        break;
            case EC::SecurityEvent:    cat = "Security";         break;
            case EC::SystemEvent:      cat = "System";           break;
            default:                   cat = "Other";            break;
            }
            t->setItem(i, 5, new QTableWidgetItem(cat));
            t->setItem(i, 6, new QTableWidgetItem(e.message.left(120)));
            if (e.isFlagged)
                for (int c = 0; c < 7; c++)
                    if (t->item(i, c)) t->item(i, c)->setBackground(QColor("#3d1515"));
        }
    };

    // ── Connections ───────────────────────────────────────────────────────
    connect(browseBtn, &QPushButton::clicked, this, [pathEdit, this] {
        QString f = QFileDialog::getOpenFileName(this, "Open Event Log", "",
            "Event Logs (*.evtx *.xml *.txt);;All Files (*)");
        if (!f.isEmpty()) pathEdit->setText(f);
    });

    connect(parser, &Forensic::Modules::EventLogParser::progressChanged,
            this, [progress](int p) { progress->setValue(p); }, Qt::QueuedConnection);

    connect(parseBtn, &QPushButton::clicked, this, [=] {
        QString path = pathEdit->text().trimmed();
        if (path.isEmpty()) { QMessageBox::warning(this,"No File","Select an event log."); return; }
        progress->setVisible(true); progress->setValue(0);
        allTable->setRowCount(0); flaggedTable->setRowCount(0);
        statusLabel->setText("Parsing...");
        QtConcurrent::run([parser, path] {
            if (path.endsWith(".xml", Qt::CaseInsensitive))
                parser->parseXmlExport(path);
            else
                parser->parseEvtxFile(path);
        });
    });

    connect(parser, &Forensic::Modules::EventLogParser::parseComplete,
            this, [=](const Forensic::Modules::EventLogSummary &s) {
        progress->setVisible(false);
        statusLabel->setText(QString(
            "✔ %1 events | Failed logins: %2 | USB: %3 | Process: %4 | Flagged: %5")
            .arg(s.totalEvents).arg(s.failedLogins).arg(s.usbEvents)
            .arg(s.processEvents).arg(s.flaggedEvents));

        // Summary table
        QList<QPair<QString,int>> rows = {
            {"Total Events",        s.totalEvents},
            {"Failed Logins",       s.failedLogins},
            {"Successful Logins",   s.successfulLogins},
            {"USB Events",          s.usbEvents},
            {"Process Executions",  s.processEvents},
            {"Application Crashes", s.crashes},
            {"Security Events",     s.securityEvents},
            {"Flagged Events",      s.flaggedEvents},
        };
        sumTable->setRowCount(rows.size());
        for (int i = 0; i < rows.size(); i++) {
            sumTable->setItem(i, 0, new QTableWidgetItem(rows[i].first));
            auto *vi = new QTableWidgetItem(QString::number(rows[i].second));
            if (rows[i].first.contains("Failed") || rows[i].first.contains("Flagged"))
                vi->setForeground(QColor("#f38ba8"));
            sumTable->setItem(i, 1, vi);
        }

        populateTable(allTable,     parser->entries());
        populateTable(flaggedTable, s.flaggedList);

        tabs->setTabText(1, QString("All Events (%1)").arg(s.totalEvents));
        tabs->setTabText(2, QString("Flagged (%1)").arg(s.flaggedEvents));
    }, Qt::QueuedConnection);

    connect(parser, &Forensic::Modules::EventLogParser::errorOccurred,
            this, [progress, statusLabel, this](const QString &e) {
        progress->setVisible(false);
        statusLabel->setText("Error: " + e);
        QMessageBox::critical(this, "Parse Error", e);
    }, Qt::QueuedConnection);
}

} // namespace Forensic::UI
