#pragma once
#include <QObject>
#include <QString>
#include <QJsonObject>
#include "ForensicCase.h"

namespace Forensic::Modules {

enum class ReportFormat { PDF, HTML, JSON };

struct ReportConfig {
    ReportFormat format{ReportFormat::PDF};
    QString      outputPath;
    QString      templatePath;
    bool         includeSummary{true};
    bool         includeTimeline{true};
    bool         includeEvidence{true};
    bool         includeNetwork{true};
    bool         includeMalware{true};
    bool         includeAiSummary{true};
    bool         includeFileSystem{true};
    bool         includeEventLogs{true};
    QString      companyName{"Digital Forensics Lab"};
    QString      logoPath;
    QString      classificationLabel{"CONFIDENTIAL"};
};

class ReportGenerator : public QObject {
    Q_OBJECT
public:
    explicit ReportGenerator(QObject *parent = nullptr);

    bool generate(const ReportConfig &config,
                  const Forensic::Core::ForensicCase &caseData,
                  const QJsonObject &analysisData);

    bool generatePdf (const ReportConfig &cfg, const Forensic::Core::ForensicCase &c,
                      const QJsonObject &data);
    bool generateHtml(const ReportConfig &cfg, const Forensic::Core::ForensicCase &c,
                      const QJsonObject &data);
    bool generateJson(const ReportConfig &cfg, const Forensic::Core::ForensicCase &c,
                      const QJsonObject &data);

signals:
    void progressChanged(int percent);
    void reportGenerated(const QString &outputPath);
    void errorOccurred(const QString &error);

private:
    QString buildHtmlContent(const ReportConfig &cfg,
                              const Forensic::Core::ForensicCase &c,
                              const QJsonObject &data) const;
    QString cssStyles() const;
    QString renderTimeline(const QJsonObject &data) const;
    QString renderEvidenceTable(const Forensic::Core::ForensicCase &c) const;
    QString renderNetworkSection(const QJsonObject &data) const;
    QString renderMalwareSection(const QJsonObject &data) const;
    QString renderAiSection(const QJsonObject &data) const;
};

} // namespace Forensic::Modules
