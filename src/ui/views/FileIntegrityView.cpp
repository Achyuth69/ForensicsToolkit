#include "FileIntegrityView.h"
#include "FileIntegrityModule.h"
#include "HashEngine.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QTableWidget>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QSplitter>
#include <QtConcurrent/QtConcurrent>

namespace Forensic::UI {

FileIntegrityView::FileIntegrityView(QWidget *parent) : QWidget(parent)
{
    auto *mod = new Forensic::Modules::FileIntegrityModule(this);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // ── Header ────────────────────────────────────────────────────────────
    auto *header = new QWidget(this);
    header->setStyleSheet("background:#181825; border-bottom:1px solid #45475a;");
    auto *hl = new QHBoxLayout(header);
    hl->setContentsMargins(16, 10, 16, 10);
    auto *title = new QLabel("🔒  File Integrity Checker", header);
    title->setStyleSheet("font-size:16px; font-weight:bold; color:#89b4fa;");
    hl->addWidget(title);
    layout->addWidget(header);

    // ── Toolbar ───────────────────────────────────────────────────────────
    auto *tb = new QWidget(this);
    tb->setStyleSheet("background:#262637; border-bottom:1px solid #45475a;");
    auto *tl = new QHBoxLayout(tb);
    tl->setContentsMargins(12, 8, 12, 8);
    tl->setSpacing(8);

    auto *dirEdit      = new QLineEdit(tb);  dirEdit->setPlaceholderText("Directory to monitor...");
    auto *snapEdit     = new QLineEdit(tb);  snapEdit->setPlaceholderText("baseline.json");
    auto *dirBrowse    = new QPushButton("Browse Dir...", tb);
    auto *snapBrowse   = new QPushButton("Browse...", tb);  snapBrowse->setFixedWidth(70);
    auto *baselineBtn  = new QPushButton("📸 Create Baseline", tb);
    auto *verifyBtn    = new QPushButton("✅ Verify", tb);
    auto *singleBtn    = new QPushButton("Check Single File", tb);
    baselineBtn->setProperty("primary", true);

    tl->addWidget(dirEdit, 1);
    tl->addWidget(dirBrowse);
    tl->addWidget(new QLabel("Snapshot:", tb));
    tl->addWidget(snapEdit, 1);
    tl->addWidget(snapBrowse);
    tl->addWidget(baselineBtn);
    tl->addWidget(verifyBtn);
    tl->addWidget(singleBtn);
    layout->addWidget(tb);

    auto *progress = new QProgressBar(this);
    progress->setRange(0, 100); progress->setVisible(false); progress->setFixedHeight(6);
    layout->addWidget(progress);

    auto *statusLabel = new QLabel("Ready — create a baseline or verify against one", this);
    statusLabel->setStyleSheet("padding:4px 16px; color:#a6adc8; font-size:12px;");
    layout->addWidget(statusLabel);

    // ── Results table ─────────────────────────────────────────────────────
    auto *table = new QTableWidget(0, 5, this);
    table->setHorizontalHeaderLabels({"File Path", "Status", "SHA-256", "Previous Hash", "Size"});
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->verticalHeader()->setVisible(false);
    table->setAlternatingRowColors(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    layout->addWidget(table, 1);

    // ── Connections ───────────────────────────────────────────────────────
    connect(dirBrowse, &QPushButton::clicked, this, [dirEdit, this] {
        QString p = QFileDialog::getExistingDirectory(this, "Select Directory");
        if (!p.isEmpty()) dirEdit->setText(p);
    });

    connect(snapBrowse, &QPushButton::clicked, this, [snapEdit, this] {
        QString p = QFileDialog::getSaveFileName(this, "Snapshot File", "baseline.json", "JSON (*.json)");
        if (!p.isEmpty()) snapEdit->setText(p);
    });

    connect(baselineBtn, &QPushButton::clicked, this, [=] {
        if (dirEdit->text().isEmpty() || snapEdit->text().isEmpty()) {
            QMessageBox::warning(this, "Missing", "Set directory and snapshot file path.");
            return;
        }
        progress->setVisible(true); progress->setValue(0);
        statusLabel->setText("Creating baseline...");
        QString dir = dirEdit->text(), snap = snapEdit->text();
        QtConcurrent::run([=] {
            bool ok = mod->createBaseline(dir, snap);
            QMetaObject::invokeMethod(this, [=] {
                progress->setVisible(false);
                statusLabel->setText(ok ? "✔ Baseline created: " + snap : "✘ Failed to create baseline");
            });
        });
    });

    connect(mod, &Forensic::Modules::FileIntegrityModule::progressChanged,
            this, [progress, statusLabel](int p, const QString &f) {
        progress->setValue(p % 100);
        statusLabel->setText(f.left(80));
    }, Qt::QueuedConnection);

    connect(verifyBtn, &QPushButton::clicked, this, [=] {
        if (dirEdit->text().isEmpty() || snapEdit->text().isEmpty()) {
            QMessageBox::warning(this, "Missing", "Set directory and snapshot file path.");
            return;
        }
        table->setRowCount(0);
        progress->setVisible(true); progress->setValue(0);
        statusLabel->setText("Verifying...");
        QString dir = dirEdit->text(), snap = snapEdit->text();
        QtConcurrent::run([=] {
            auto results = mod->verifyAgainstBaseline(dir, snap);
            QMetaObject::invokeMethod(this, [=] {
                progress->setVisible(false);
                table->setRowCount(results.size());
                int modified = 0, missing = 0;
                for (int i = 0; i < results.size(); i++) {
                    const auto &r = results[i];
                    table->setItem(i, 0, new QTableWidgetItem(r.path));
                    QString s = Forensic::Modules::FileIntegrityModule::statusString(r.status);
                    auto *si = new QTableWidgetItem(s);
                    if (r.status == Forensic::Modules::IntegrityStatus::Modified ||
                        r.status == Forensic::Modules::IntegrityStatus::Tampered)
                    { si->setForeground(QColor("#f38ba8")); modified++; }
                    else if (r.status == Forensic::Modules::IntegrityStatus::Missing)
                    { si->setForeground(QColor("#f38ba8")); missing++; }
                    else if (r.status == Forensic::Modules::IntegrityStatus::Clean)
                    { si->setForeground(QColor("#a6e3a1")); }
                    else if (r.status == Forensic::Modules::IntegrityStatus::New)
                    { si->setForeground(QColor("#f9e2af")); }
                    table->setItem(i, 1, si);
                    table->setItem(i, 2, new QTableWidgetItem(r.sha256.left(20)+"..."));
                    table->setItem(i, 3, new QTableWidgetItem(r.previousHash.left(20)+"..."));
                    table->setItem(i, 4, new QTableWidgetItem(QString::number(r.size/1024)+" KB"));
                }
                statusLabel->setText(QString("✔ Complete — Total: %1 | Modified: %2 | Missing: %3")
                    .arg(results.size()).arg(modified).arg(missing));
            });
        });
    });

    connect(singleBtn, &QPushButton::clicked, this, [=] {
        QString f = QFileDialog::getOpenFileName(this, "Select File to Check");
        if (f.isEmpty()) return;
        auto r = mod->checkFile(f);
        QMessageBox::information(this, "File Hash Result",
            QString("Path:   %1\nSHA-256: %2\nSHA-1:   %3\nMD5:    %4\nSize:   %5 KB\nStatus: %6")
            .arg(r.path, r.sha256, r.sha1, r.md5)
            .arg(r.size / 1024)
            .arg(Forensic::Modules::FileIntegrityModule::statusString(r.status)));
    });
}

} // namespace Forensic::UI
