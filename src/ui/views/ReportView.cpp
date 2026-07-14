#include "ReportView.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QLabel>
#include <QGroupBox>
#include <QFileDialog>
#include <QMessageBox>
#include <QDesktopServices>
#include <QUrl>
#include <QDir>
#include <QFileInfo>

namespace Forensic::UI {

ReportView::ReportView(QWidget *parent) : QWidget(parent) {
    m_generator = std::make_unique<Forensic::Modules::ReportGenerator>(this);
    connect(m_generator.get(), &Forensic::Modules::ReportGenerator::progressChanged,
            this, &ReportView::onProgress);
    connect(m_generator.get(), &Forensic::Modules::ReportGenerator::reportGenerated,
            this, &ReportView::onReportGenerated);
    connect(m_generator.get(), &Forensic::Modules::ReportGenerator::errorOccurred,
            this, &ReportView::onError);
    setupUi();
}

void ReportView::setupUi() {
    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    // Header
    auto *header = new QWidget(this);
    header->setStyleSheet("background:#181825; border-bottom:1px solid #45475a;");
    auto *hl = new QHBoxLayout(header);
    hl->setContentsMargins(16, 10, 16, 10);
    auto *title = new QLabel("📊  Report Generator", header);
    title->setStyleSheet("font-size:16px; font-weight:bold; color:#89b4fa;");
    hl->addWidget(title);
    mainLayout->addWidget(header);

    // Content area: left config panel + right preview
    auto *content = new QWidget(this);
    auto *cl = new QHBoxLayout(content);
    cl->setContentsMargins(20, 16, 20, 16);
    cl->setSpacing(20);

    // ── Left: configuration ───────────────────────────────────────────────
    auto *configWidget = new QWidget(content);
    auto *configLayout = new QVBoxLayout(configWidget);
    configLayout->setSpacing(12);
    configLayout->setContentsMargins(0, 0, 0, 0);

    // Format
    m_formatGrp = new QGroupBox("Output Format", configWidget);
    auto *ffl = new QHBoxLayout(m_formatGrp);
    m_formatCombo = new QComboBox(m_formatGrp);
    m_formatCombo->addItems({"PDF", "HTML", "JSON"});
    ffl->addWidget(new QLabel("Format:", m_formatGrp));
    ffl->addWidget(m_formatCombo, 1);

    // Content sections
    m_contentGrp = new QGroupBox("Include Sections", configWidget);
    auto *cgl = new QGridLayout(m_contentGrp);
    m_cbTimeline   = new QCheckBox("Timeline",           m_contentGrp); m_cbTimeline->setChecked(true);
    m_cbEvidence   = new QCheckBox("Evidence Inventory", m_contentGrp); m_cbEvidence->setChecked(true);
    m_cbNetwork    = new QCheckBox("Network Analysis",   m_contentGrp); m_cbNetwork->setChecked(true);
    m_cbMalware    = new QCheckBox("Malware Findings",   m_contentGrp); m_cbMalware->setChecked(true);
    m_cbAiSummary  = new QCheckBox("AI Summary",         m_contentGrp); m_cbAiSummary->setChecked(true);
    m_cbFileSystem = new QCheckBox("File System",        m_contentGrp); m_cbFileSystem->setChecked(true);
    m_cbEventLogs  = new QCheckBox("Event Logs",         m_contentGrp); m_cbEventLogs->setChecked(true);
    cgl->addWidget(m_cbTimeline,   0, 0); cgl->addWidget(m_cbEvidence,   0, 1);
    cgl->addWidget(m_cbNetwork,    1, 0); cgl->addWidget(m_cbMalware,    1, 1);
    cgl->addWidget(m_cbFileSystem, 2, 0); cgl->addWidget(m_cbEventLogs,  2, 1);
    cgl->addWidget(m_cbAiSummary,  3, 0);

    // Branding
    m_brandingGrp = new QGroupBox("Report Branding", configWidget);
    auto *bgl = new QGridLayout(m_brandingGrp);
    m_companyEdit = new QLineEdit("Digital Forensics Laboratory", m_brandingGrp);
    m_classLabel  = new QLineEdit("CONFIDENTIAL", m_brandingGrp);
    m_logoEdit    = new QLineEdit(m_brandingGrp);
    auto *logoBrowse = new QPushButton("...", m_brandingGrp); logoBrowse->setFixedWidth(30);
    auto *logoRow = new QHBoxLayout();
    logoRow->addWidget(m_logoEdit, 1); logoRow->addWidget(logoBrowse);
    connect(logoBrowse, &QPushButton::clicked, this, &ReportView::onBrowseLogo);
    bgl->addWidget(new QLabel("Organization:", m_brandingGrp), 0, 0); bgl->addWidget(m_companyEdit, 0, 1);
    bgl->addWidget(new QLabel("Classification:", m_brandingGrp), 1, 0); bgl->addWidget(m_classLabel, 1, 1);
    bgl->addWidget(new QLabel("Logo:", m_brandingGrp), 2, 0); bgl->addLayout(logoRow, 2, 1);

    // Output
    m_outputGrp = new QGroupBox("Output File", configWidget);
    auto *ogl = new QGridLayout(m_outputGrp);
    m_outputEdit = new QLineEdit(m_outputGrp);
    m_outputEdit->setPlaceholderText("report.pdf / report.html / report.json");
    auto *outBrowse = new QPushButton("...", m_outputGrp); outBrowse->setFixedWidth(30);
    connect(outBrowse, &QPushButton::clicked, this, &ReportView::onBrowseOutput);
    auto *outRow = new QHBoxLayout();
    outRow->addWidget(m_outputEdit, 1); outRow->addWidget(outBrowse);
    ogl->addWidget(new QLabel("Save to:", m_outputGrp), 0, 0); ogl->addLayout(outRow, 0, 1);

    // Buttons
    auto *btnRow = new QHBoxLayout();
    auto *genBtn     = new QPushButton("📄 Generate Report", configWidget);
    auto *previewBtn = new QPushButton("👁 Preview in Browser", configWidget);
    genBtn->setProperty("primary", true);
    connect(genBtn,     &QPushButton::clicked, this, &ReportView::onGenerate);
    connect(previewBtn, &QPushButton::clicked, this, &ReportView::onPreview);
    btnRow->addWidget(genBtn); btnRow->addWidget(previewBtn);

    m_progress = new QProgressBar(configWidget);
    m_progress->setRange(0, 100); m_progress->setVisible(false);
    m_statusLabel = new QLabel("Configure options above and click Generate", configWidget);
    m_statusLabel->setStyleSheet("color:#a6adc8; font-size:11px;");
    m_statusLabel->setWordWrap(true);

    configLayout->addWidget(m_formatGrp);
    configLayout->addWidget(m_contentGrp);
    configLayout->addWidget(m_brandingGrp);
    configLayout->addWidget(m_outputGrp);
    configLayout->addLayout(btnRow);
    configLayout->addWidget(m_progress);
    configLayout->addWidget(m_statusLabel);
    configLayout->addStretch();

    // ── Right: preview ────────────────────────────────────────────────────
    m_previewEdit = new QTextEdit(content);
    m_previewEdit->setReadOnly(true);
    m_previewEdit->setFont(QFont("Consolas", 10));
    m_previewEdit->setPlaceholderText("HTML preview will appear here after generation...");
    m_previewEdit->setMinimumWidth(380);

    cl->addWidget(configWidget, 0);
    cl->addWidget(m_previewEdit, 1);

    mainLayout->addWidget(content, 1);
}

void ReportView::setupFormatSection()   {}
void ReportView::setupContentSection()  {}
void ReportView::setupBrandingSection() {}
void ReportView::setupOutputSection()   {}

void ReportView::setCaseData(const Forensic::Core::ForensicCase &c)  { m_caseData = c; }
void ReportView::setAnalysisData(const QJsonObject &data)            { m_analysisData = data; }

void ReportView::onBrowseOutput() {
    QString fmt    = m_formatCombo->currentText();
    QString filter = fmt=="PDF" ? "PDF (*.pdf)" : fmt=="HTML" ? "HTML (*.html)" : "JSON (*.json)";
    QString ext    = fmt=="PDF" ? ".pdf"         : fmt=="HTML" ? ".html"         : ".json";
    QString path   = QFileDialog::getSaveFileName(this, "Save Report", "report"+ext, filter);
    if (!path.isEmpty()) m_outputEdit->setText(path);
}

void ReportView::onBrowseLogo() {
    QString f = QFileDialog::getOpenFileName(this, "Select Logo", "", "Images (*.png *.jpg *.svg)");
    if (!f.isEmpty()) m_logoEdit->setText(f);
}

void ReportView::onBrowseTemplate() {}

void ReportView::onGenerate() {
    QString out = m_outputEdit->text().trimmed();
    if (out.isEmpty()) { QMessageBox::warning(this, "No Output", "Specify an output file path."); return; }

    Forensic::Modules::ReportConfig cfg;
    cfg.outputPath          = out;
    cfg.companyName         = m_companyEdit->text();
    cfg.classificationLabel = m_classLabel->text();
    cfg.logoPath            = m_logoEdit->text();
    cfg.includeTimeline     = m_cbTimeline->isChecked();
    cfg.includeEvidence     = m_cbEvidence->isChecked();
    cfg.includeNetwork      = m_cbNetwork->isChecked();
    cfg.includeMalware      = m_cbMalware->isChecked();
    cfg.includeAiSummary    = m_cbAiSummary->isChecked();
    cfg.includeFileSystem   = m_cbFileSystem->isChecked();
    cfg.includeEventLogs    = m_cbEventLogs->isChecked();
    QString fmt = m_formatCombo->currentText();
    if      (fmt=="PDF")  cfg.format = Forensic::Modules::ReportFormat::PDF;
    else if (fmt=="HTML") cfg.format = Forensic::Modules::ReportFormat::HTML;
    else                  cfg.format = Forensic::Modules::ReportFormat::JSON;

    m_progress->setVisible(true); m_progress->setValue(0);
    m_statusLabel->setText("Generating report...");
    m_generator->generate(cfg, m_caseData, m_analysisData);
}

void ReportView::onPreview() {
    Forensic::Modules::ReportConfig cfg;
    cfg.format              = Forensic::Modules::ReportFormat::HTML;
    cfg.outputPath          = QDir::tempPath() + "/forensic_preview.html";
    cfg.companyName         = m_companyEdit->text();
    cfg.classificationLabel = m_classLabel->text();
    cfg.includeTimeline     = m_cbTimeline->isChecked();
    cfg.includeEvidence     = m_cbEvidence->isChecked();
    cfg.includeNetwork      = m_cbNetwork->isChecked();
    cfg.includeMalware      = m_cbMalware->isChecked();
    cfg.includeAiSummary    = m_cbAiSummary->isChecked();
    cfg.includeFileSystem   = m_cbFileSystem->isChecked();
    cfg.includeEventLogs    = m_cbEventLogs->isChecked();
    if (m_generator->generateHtml(cfg, m_caseData, m_analysisData)) {
        QFile f(cfg.outputPath);
        if (f.open(QIODevice::ReadOnly | QIODevice::Text))
            m_previewEdit->setHtml(QString::fromUtf8(f.readAll()));
        QDesktopServices::openUrl(QUrl::fromLocalFile(cfg.outputPath));
        m_statusLabel->setText("Preview opened in browser");
    }
}

void ReportView::onProgress(int p) { m_progress->setValue(p); }

void ReportView::onReportGenerated(const QString &path) {
    m_progress->setVisible(false);
    m_statusLabel->setText("✔ Report saved: " + path);
    if (QMessageBox::question(this, "Report Generated",
            "Report saved:\n" + path + "\n\nOpen it now?") == QMessageBox::Yes)
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
}

void ReportView::onError(const QString &err) {
    m_progress->setVisible(false);
    m_statusLabel->setText("Error: " + err);
    QMessageBox::critical(this, "Report Error", err);
}

} // namespace Forensic::UI
