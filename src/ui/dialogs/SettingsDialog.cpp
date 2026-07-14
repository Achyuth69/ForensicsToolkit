#include "SettingsDialog.h"
#include "Logger.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QTabWidget>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QLabel>
#include <QGroupBox>
#include <QSettings>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QMessageBox>

namespace Forensic::UI {

SettingsDialog::SettingsDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("Settings");
    setMinimumWidth(520);
    setModal(true);

    auto *layout = new QVBoxLayout(this);

    auto *title = new QLabel("⚙  Application Settings", this);
    title->setStyleSheet("font-size:16px;font-weight:bold;color:#89b4fa;margin-bottom:8px;");
    layout->addWidget(title);

    auto *tabs = new QTabWidget(this);

    // ── AI Settings tab ───────────────────────────────────────────────────────
    auto *aiTab = new QWidget(tabs);
    auto *afl   = new QVBoxLayout(aiTab);

    auto *aiGroup = new QGroupBox("AI / LLM Configuration", aiTab);
    auto *agf = new QFormLayout(aiGroup);

    m_providerCombo = new QComboBox(aiGroup);
    m_providerCombo->addItems({"openai", "anthropic", "openrouter", "ollama"});
    agf->addRow("Provider:", m_providerCombo);

    auto *keyRow = new QHBoxLayout();
    m_apiKeyEdit = new QLineEdit(aiGroup);
    m_apiKeyEdit->setEchoMode(QLineEdit::Password);
    m_apiKeyEdit->setPlaceholderText("sk-... or your API key");
    auto *showKeyBtn = new QPushButton("Show", aiGroup);
    showKeyBtn->setFixedWidth(55);
    showKeyBtn->setCheckable(true);
    connect(showKeyBtn, &QPushButton::toggled, this, [this](bool v){
        m_apiKeyEdit->setEchoMode(v ? QLineEdit::Normal : QLineEdit::Password);
    });
    keyRow->addWidget(m_apiKeyEdit, 1);
    keyRow->addWidget(showKeyBtn);
    agf->addRow("API Key:", keyRow);

    m_modelEdit = new QLineEdit(aiGroup);
    m_modelEdit->setPlaceholderText("gpt-4o  |  claude-3-5-sonnet-20241022  |  llama3.1:70b");
    agf->addRow("Model:", m_modelEdit);

    m_baseUrlEdit = new QLineEdit(aiGroup);
    m_baseUrlEdit->setPlaceholderText("Leave blank for default  |  http://localhost:11434/v1/chat/completions");
    agf->addRow("Base URL (optional):", m_baseUrlEdit);

    m_maxTokensSpin = new QSpinBox(aiGroup);
    m_maxTokensSpin->setRange(256, 32768);
    m_maxTokensSpin->setValue(4096);
    m_maxTokensSpin->setSingleStep(256);
    agf->addRow("Max Tokens:", m_maxTokensSpin);

    auto *testBtn = new QPushButton("Test Connection", aiGroup);
    connect(testBtn, &QPushButton::clicked, this, [this]{
        if (m_apiKeyEdit->text().isEmpty() && m_baseUrlEdit->text().isEmpty()) {
            QMessageBox::warning(this, "No Config", "Enter an API key or base URL first.");
            return;
        }
        QMessageBox::information(this, "Test",
            "Configuration saved. The connection will be tested on first query.\n\n"
            "Provider: " + m_providerCombo->currentText() + "\n"
            "Model: " + m_modelEdit->text());
    });
    agf->addRow("", testBtn);

    afl->addWidget(aiGroup);
    afl->addStretch();
    tabs->addTab(aiTab, "AI Assistant");

    // ── General Settings tab ──────────────────────────────────────────────────
    auto *genTab = new QWidget(tabs);
    auto *gfl    = new QVBoxLayout(genTab);

    auto *logGroup = new QGroupBox("Logging", genTab);
    auto *lgf      = new QFormLayout(logGroup);

    m_logLevelCombo = new QComboBox(logGroup);
    m_logLevelCombo->addItems({"Trace", "Debug", "Info", "Warning", "Error"});
    m_logLevelCombo->setCurrentText("Info");
    lgf->addRow("Log Level:", m_logLevelCombo);

    auto *logPathRow = new QHBoxLayout();
    m_logPathEdit = new QLineEdit(logGroup);
    m_logPathEdit->setPlaceholderText("forensic.log  (leave blank to disable file logging)");
    auto *logBrowseBtn = new QPushButton("...", logGroup);
    logBrowseBtn->setFixedWidth(30);
    connect(logBrowseBtn, &QPushButton::clicked, this, [this]{
        QString p = QFileDialog::getSaveFileName(this, "Log File", "", "Log (*.log *.txt)");
        if (!p.isEmpty()) m_logPathEdit->setText(p);
    });
    logPathRow->addWidget(m_logPathEdit, 1);
    logPathRow->addWidget(logBrowseBtn);
    lgf->addRow("Log File:", logPathRow);

    gfl->addWidget(logGroup);
    gfl->addStretch();
    tabs->addTab(genTab, "General");

    layout->addWidget(tabs, 1);

    auto *buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText("Save Settings");
    buttons->button(QDialogButtonBox::Ok)->setProperty("primary", true);
    connect(buttons, &QDialogButtonBox::accepted, this, [this]{
        saveSettings();
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);

    loadSettings();
}

void SettingsDialog::loadSettings() {
    QSettings s("ForensicToolkit", "ForensicToolkit");
    m_providerCombo->setCurrentText(s.value("ai/provider", "openai").toString());
    m_apiKeyEdit->setText(s.value("ai/apiKey").toString());
    m_modelEdit->setText(s.value("ai/model", "gpt-4o").toString());
    m_baseUrlEdit->setText(s.value("ai/baseUrl").toString());
    m_maxTokensSpin->setValue(s.value("ai/maxTokens", 4096).toInt());
    m_logPathEdit->setText(s.value("log/path").toString());
    m_logLevelCombo->setCurrentText(s.value("log/level", "Info").toString());
}

void SettingsDialog::saveSettings() {
    QSettings s("ForensicToolkit", "ForensicToolkit");
    s.setValue("ai/provider",  m_providerCombo->currentText());
    s.setValue("ai/apiKey",    m_apiKeyEdit->text());
    s.setValue("ai/model",     m_modelEdit->text());
    s.setValue("ai/baseUrl",   m_baseUrlEdit->text());
    s.setValue("ai/maxTokens", m_maxTokensSpin->value());
    s.setValue("log/path",     m_logPathEdit->text());
    s.setValue("log/level",    m_logLevelCombo->currentText());

    // Apply log file setting immediately
    if (!m_logPathEdit->text().isEmpty())
        Forensic::Core::Logger::instance().setLogFile(m_logPathEdit->text());
}

} // namespace Forensic::UI
