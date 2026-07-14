#include "LogView.h"
#include "Logger.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QLineEdit>
#include <QTextEdit>
#include <QScrollBar>
#include <QFont>
#include <QFileDialog>
#include <QTextStream>
#include <QDateTime>

namespace Forensic::UI {

LogView::LogView(QWidget *parent) : QWidget(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // ── Header ────────────────────────────────────────────────────────────
    auto *header = new QWidget(this);
    header->setStyleSheet("background:#181825; border-bottom:1px solid #45475a;");
    auto *hl = new QHBoxLayout(header);
    hl->setContentsMargins(16, 10, 16, 10);

    auto *title      = new QLabel("📝  System Log", header);
    title->setStyleSheet("font-size:16px; font-weight:bold; color:#89b4fa;");
    auto *countLabel = new QLabel("0 entries", header);
    countLabel->setStyleSheet("color:#a6adc8; font-size:11px;");

    auto *clearBtn   = new QPushButton("🗑 Clear",        header);
    auto *exportBtn  = new QPushButton("💾 Export",       header);
    auto *scrollBtn  = new QPushButton("⬇ Auto-scroll",  header);
    scrollBtn->setCheckable(true);
    scrollBtn->setChecked(true);

    hl->addWidget(title, 1);
    hl->addWidget(countLabel);
    hl->addWidget(scrollBtn);
    hl->addWidget(clearBtn);
    hl->addWidget(exportBtn);
    layout->addWidget(header);

    // ── Filter bar ────────────────────────────────────────────────────────
    auto *filterBar = new QWidget(this);
    filterBar->setStyleSheet("background:#262637; border-bottom:1px solid #45475a;");
    auto *fl = new QHBoxLayout(filterBar);
    fl->setContentsMargins(12, 6, 12, 6);

    auto *levelCombo = new QComboBox(filterBar);
    levelCombo->addItems({"All","INFO","WARN","ERROR","CRIT"});
    levelCombo->setFixedWidth(90);

    auto *searchEdit = new QLineEdit(filterBar);
    searchEdit->setPlaceholderText("Search log entries...");
    searchEdit->setFixedWidth(280);

    fl->addWidget(new QLabel("Level:", filterBar));
    fl->addWidget(levelCombo);
    fl->addSpacing(16);
    fl->addWidget(new QLabel("Filter:", filterBar));
    fl->addWidget(searchEdit);
    fl->addStretch();
    layout->addWidget(filterBar);

    // ── Log output ────────────────────────────────────────────────────────
    auto *logEdit = new QTextEdit(this);
    logEdit->setReadOnly(true);
    logEdit->setFont(QFont("Consolas", 10));
    logEdit->setStyleSheet("background:#0d0d0d; color:#a6e3a1; border:none; padding:8px;");
    logEdit->document()->setMaximumBlockCount(10000);
    layout->addWidget(logEdit, 1);

    // ── State ─────────────────────────────────────────────────────────────
    int *entryCount = new int(0);  // stored on heap, owned by this widget lifetime

    // ── Connections ───────────────────────────────────────────────────────
    connect(clearBtn, &QPushButton::clicked, this, [logEdit, countLabel, entryCount] {
        logEdit->clear();
        *entryCount = 0;
        countLabel->setText("0 entries");
    });

    connect(exportBtn, &QPushButton::clicked, this, [logEdit, this] {
        QString p = QFileDialog::getSaveFileName(this, "Save Log", "forensic.log", "Log (*.log *.txt)");
        if (p.isEmpty()) return;
        QFile f(p);
        if (f.open(QIODevice::WriteOnly | QIODevice::Text))
            QTextStream(&f) << logEdit->toPlainText();
    });

    // ── Logger sink ───────────────────────────────────────────────────────
    Forensic::Core::Logger::instance().addSink(
        [this, logEdit, countLabel, entryCount, levelCombo, searchEdit, scrollBtn]
        (const Forensic::Core::LogEntry &entry)
    {
        QMetaObject::invokeMethod(this, [=] {
            // Level filter
            auto lvlStr = [](Forensic::Core::LogLevel l) -> QString {
                switch (l) {
                case Forensic::Core::LogLevel::Trace:    return "TRACE";
                case Forensic::Core::LogLevel::Debug:    return "DEBUG";
                case Forensic::Core::LogLevel::Info:     return "INFO";
                case Forensic::Core::LogLevel::Warning:  return "WARN";
                case Forensic::Core::LogLevel::Error:    return "ERROR";
                case Forensic::Core::LogLevel::Critical: return "CRIT";
                }
                return "????";
            };
            QString ls = lvlStr(entry.level);
            if (levelCombo->currentText() != "All" && levelCombo->currentText() != ls) return;
            if (!searchEdit->text().isEmpty() &&
                !entry.message.contains(searchEdit->text(), Qt::CaseInsensitive)) return;

            auto color = [](Forensic::Core::LogLevel l) -> QString {
                switch (l) {
                case Forensic::Core::LogLevel::Trace:    return "#6c7086";
                case Forensic::Core::LogLevel::Debug:    return "#89b4fa";
                case Forensic::Core::LogLevel::Info:     return "#a6e3a1";
                case Forensic::Core::LogLevel::Warning:  return "#f9e2af";
                case Forensic::Core::LogLevel::Error:    return "#f38ba8";
                case Forensic::Core::LogLevel::Critical: return "#d20f39";
                }
                return "#cdd6f4";
            };
            QString c = color(entry.level);
            QString html = QString(
                "<span style='color:#6c7086'>%1</span> "
                "<span style='color:%2; font-weight:bold'>[%3]</span> "
                "<span style='color:#585b70'>[%4]</span> "
                "<span style='color:%2'>%5</span>")
                .arg(entry.timestamp.toString("hh:mm:ss.zzz"),
                     c, ls.leftJustified(5),
                     entry.source.isEmpty() ? "core" : entry.source,
                     entry.message.toHtmlEscaped());
            logEdit->append(html);
            (*entryCount)++;
            countLabel->setText(QString::number(*entryCount) + " entries");
            if (scrollBtn->isChecked())
                logEdit->verticalScrollBar()->setValue(
                    logEdit->verticalScrollBar()->maximum());
        }, Qt::QueuedConnection);
    });

    // Initial message
    logEdit->append(
        QString("<span style='color:#6c7086'>[%1] [SYSTEM] ForensicToolkit log initialized</span>")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss.zzz")));
}

} // namespace Forensic::UI
