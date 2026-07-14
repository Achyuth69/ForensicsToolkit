#pragma once
#include <QWidget>
#include <QComboBox>
#include <QCheckBox>
#include <QLineEdit>
#include <QProgressBar>
#include <QLabel>
#include <QTextEdit>
#include <QGroupBox>
#include <QFont>
#include <memory>
#include "ReportGenerator.h"
#include "ForensicCase.h"

namespace Forensic::UI {

class ReportView : public QWidget {
    Q_OBJECT
public:
    explicit ReportView(QWidget *parent = nullptr);
    void setCaseData(const Forensic::Core::ForensicCase &c);
    void setAnalysisData(const QJsonObject &data);

private slots:
    void onBrowseOutput();
    void onBrowseLogo();
    void onBrowseTemplate();
    void onGenerate();
    void onPreview();
    void onProgress(int pct);
    void onReportGenerated(const QString &path);
    void onError(const QString &error);

private:
    void setupUi();
    void setupFormatSection();
    void setupContentSection();
    void setupBrandingSection();
    void setupOutputSection();

    QGroupBox   *m_formatGrp{nullptr};
    QGroupBox   *m_contentGrp{nullptr};
    QGroupBox   *m_brandingGrp{nullptr};
    QGroupBox   *m_outputGrp{nullptr};
    QComboBox   *m_formatCombo{nullptr};
    QCheckBox   *m_cbTimeline{nullptr};
    QCheckBox   *m_cbEvidence{nullptr};
    QCheckBox   *m_cbNetwork{nullptr};
    QCheckBox   *m_cbMalware{nullptr};
    QCheckBox   *m_cbAiSummary{nullptr};
    QCheckBox   *m_cbFileSystem{nullptr};
    QCheckBox   *m_cbEventLogs{nullptr};
    QLineEdit   *m_companyEdit{nullptr};
    QLineEdit   *m_logoEdit{nullptr};
    QLineEdit   *m_outputEdit{nullptr};
    QLineEdit   *m_classLabel{nullptr};
    QProgressBar *m_progress{nullptr};
    QLabel      *m_statusLabel{nullptr};
    QTextEdit   *m_previewEdit{nullptr};

    std::unique_ptr<Forensic::Modules::ReportGenerator> m_generator;
    Forensic::Core::ForensicCase m_caseData;
    QJsonObject                  m_analysisData;
};

} // namespace Forensic::UI
