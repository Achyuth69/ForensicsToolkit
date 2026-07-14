#include "ReportGenerator.h"
#include "Logger.h"
#include <QFile>
#include <QTextStream>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QPrinter>
#include <QPainter>
#include <QTextDocument>
#include <QPageLayout>
#include <QPageSize>
#include <QDir>

namespace Forensic::Modules {

ReportGenerator::ReportGenerator(QObject *parent) : QObject(parent) {}

bool ReportGenerator::generate(const ReportConfig &config,
                                const Forensic::Core::ForensicCase &caseData,
                                const QJsonObject &analysisData) {
    switch (config.format) {
    case ReportFormat::PDF:  return generatePdf (config, caseData, analysisData);
    case ReportFormat::HTML: return generateHtml(config, caseData, analysisData);
    case ReportFormat::JSON: return generateJson(config, caseData, analysisData);
    }
    return false;
}

bool ReportGenerator::generateHtml(const ReportConfig &cfg,
                                    const Forensic::Core::ForensicCase &c,
                                    const QJsonObject &data) {
    emit progressChanged(10);
    QString html = buildHtmlContent(cfg, c, data);
    emit progressChanged(80);

    QFile f(cfg.outputPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        emit errorOccurred("Cannot write HTML: " + cfg.outputPath);
        return false;
    }
    QTextStream ts(&f);
    ts << html;
    f.close();

    emit progressChanged(100);
    emit reportGenerated(cfg.outputPath);
    LOG_INFO("HTML report generated: " + cfg.outputPath);
    return true;
}

bool ReportGenerator::generatePdf(const ReportConfig &cfg,
                                   const Forensic::Core::ForensicCase &c,
                                   const QJsonObject &data) {
    emit progressChanged(10);
    QString html = buildHtmlContent(cfg, c, data);
    emit progressChanged(50);

    QTextDocument doc;
    doc.setHtml(html);
    doc.setPageSize(QSizeF(794, 1123)); // A4

    QPrinter printer(QPrinter::HighResolution);
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setOutputFileName(cfg.outputPath);
    printer.setPageSize(QPageSize(QPageSize::A4));
    QPageLayout layout;
    layout.setPageSize(QPageSize(QPageSize::A4));
    layout.setUnits(QPageLayout::Millimeter);
    layout.setMargins(QMarginsF(20, 20, 20, 20));
    printer.setPageLayout(layout);

    emit progressChanged(75);
    doc.print(&printer);
    emit progressChanged(100);
    emit reportGenerated(cfg.outputPath);
    LOG_INFO("PDF report generated: " + cfg.outputPath);
    return true;
}

bool ReportGenerator::generateJson(const ReportConfig &cfg,
                                    const Forensic::Core::ForensicCase &c,
                                    const QJsonObject &data) {
    emit progressChanged(10);

    QJsonObject report{
        {"reportMetadata", QJsonObject{
            {"generatedAt",      QDateTime::currentDateTime().toString(Qt::ISODate)},
            {"classification",   cfg.classificationLabel},
            {"company",          cfg.companyName},
            {"formatVersion",    "1.0"}
        }},
        {"case",       c.toJson()},
        {"analysis",   data}
    };

    emit progressChanged(70);

    QFile f(cfg.outputPath);
    if (!f.open(QIODevice::WriteOnly)) {
        emit errorOccurred("Cannot write JSON: " + cfg.outputPath);
        return false;
    }
    f.write(QJsonDocument(report).toJson(QJsonDocument::Indented));
    f.close();

    emit progressChanged(100);
    emit reportGenerated(cfg.outputPath);
    LOG_INFO("JSON report generated: " + cfg.outputPath);
    return true;
}

// ─── HTML Builder ─────────────────────────────────────────────────────────────
QString ReportGenerator::buildHtmlContent(const ReportConfig &cfg,
                                           const Forensic::Core::ForensicCase &c,
                                           const QJsonObject &data) const {
    QString html = R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Digital Forensics Report - )" + c.title + R"(</title>
<style>)" + cssStyles() + R"(</style>
</head>
<body>
)";

    // ── Cover page ────────────────────────────────────────────────────────────
    html += R"(<div class="cover-page">
  <div class="classification-banner">)" + cfg.classificationLabel + R"(</div>
  <div class="cover-content">
    <div class="company-name">)" + cfg.companyName.toHtmlEscaped() + R"(</div>
    <h1 class="report-title">Digital Forensics Investigation Report</h1>
    <div class="case-title">)" + c.title.toHtmlEscaped() + R"(</div>
    <table class="cover-table">
      <tr><td>Case Number:</td><td><strong>)" + c.caseNumber.toHtmlEscaped() + R"(</strong></td></tr>
      <tr><td>Status:</td><td><span class="badge badge-)" + c.statusString().toLower().replace(' ', '-') + R"(">)" + c.statusString() + R"(</span></td></tr>
      <tr><td>Date Created:</td><td>)" + c.createdAt.toString("MMMM d, yyyy") + R"(</td></tr>
      <tr><td>Report Generated:</td><td>)" + QDateTime::currentDateTime().toString("MMMM d, yyyy hh:mm") + R"(</td></tr>
      <tr><td>Evidence Items:</td><td>)" + QString::number(c.evidence.size()) + R"(</td></tr>
    </table>
  </div>
  <div class="classification-banner">)" + cfg.classificationLabel + R"(</div>
</div>
<div class="page-break"></div>
)";

    // ── Table of Contents ─────────────────────────────────────────────────────
    html += R"(<div class="section">
  <h2>Table of Contents</h2>
  <ol class="toc">
    <li><a href="#case-overview">Case Overview</a></li>
    <li><a href="#investigators">Investigators</a></li>
    <li><a href="#evidence">Evidence Inventory</a></li>)";
    if (cfg.includeTimeline)    html += R"(<li><a href="#timeline">Timeline</a></li>)";
    if (cfg.includeFileSystem)  html += R"(<li><a href="#filesystem">File System Analysis</a></li>)";
    if (cfg.includeNetwork)     html += R"(<li><a href="#network">Network Analysis</a></li>)";
    if (cfg.includeMalware)     html += R"(<li><a href="#malware">Malware Findings</a></li>)";
    if (cfg.includeEventLogs)   html += R"(<li><a href="#eventlogs">Event Log Analysis</a></li>)";
    if (cfg.includeAiSummary)   html += R"(<li><a href="#ai-analysis">AI Investigation Summary</a></li>)";
    html += R"(  </ol>
</div>)";

    // ── Case Overview ─────────────────────────────────────────────────────────
    html += R"(<div class="section" id="case-overview">
  <h2>1. Case Overview</h2>
  <table class="data-table">
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Case Title</td><td>)" + c.title.toHtmlEscaped() + R"(</td></tr>
    <tr><td>Case Number</td><td>)" + c.caseNumber.toHtmlEscaped() + R"(</td></tr>
    <tr><td>Status</td><td>)" + c.statusString() + R"(</td></tr>
    <tr><td>Description</td><td>)" + c.description.toHtmlEscaped() + R"(</td></tr>
    <tr><td>Created</td><td>)" + c.createdAt.toString(Qt::ISODate) + R"(</td></tr>
    <tr><td>Last Updated</td><td>)" + c.updatedAt.toString(Qt::ISODate) + R"(</td></tr>
  </table>
</div>)";

    // ── Investigators ─────────────────────────────────────────────────────────
    html += R"(<div class="section" id="investigators">
  <h2>2. Investigators</h2>
  <table class="data-table">
    <tr><th>Name</th><th>Badge</th><th>Role</th><th>Email</th><th>Assigned</th></tr>)";
    for (const auto &inv : c.investigators) {
        html += QString("<tr><td>%1</td><td>%2</td><td>%3</td><td>%4</td><td>%5</td></tr>")
            .arg(inv.name.toHtmlEscaped(), inv.badge.toHtmlEscaped(),
                 inv.role.toHtmlEscaped(), inv.email.toHtmlEscaped(),
                 inv.assignedAt.toString("yyyy-MM-dd"));
    }
    html += R"(  </table>
</div>)";

    // ── Evidence ──────────────────────────────────────────────────────────────
    html += renderEvidenceTable(c);

    // ── Timeline ──────────────────────────────────────────────────────────────
    if (cfg.includeTimeline) html += renderTimeline(data);

    // ── File System ───────────────────────────────────────────────────────────
    if (cfg.includeFileSystem && data.contains("filesystem")) {
        QJsonObject fs = data["filesystem"].toObject();
        QJsonObject sum = fs["summary"].toObject();
        html += R"(<div class="section" id="filesystem">
  <h2>File System Analysis</h2>
  <table class="data-table">
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Total Files</td><td>)" + QString::number(sum["totalFiles"].toInt()) + R"(</td></tr>
    <tr><td>Total Directories</td><td>)" + QString::number(sum["totalDirs"].toInt()) + R"(</td></tr>
    <tr><td>Hidden Files</td><td>)" + QString::number(sum["hiddenFiles"].toInt()) + R"(</td></tr>
    <tr><td>Duplicate Files</td><td>)" + QString::number(sum["duplicates"].toInt()) + R"(</td></tr>
    <tr><td>Total Size</td><td>)" + QString::number(sum["totalSizeBytes"].toVariant().toLongLong() / 1024 / 1024) + R"( MB</td></tr>
  </table>
</div>)";
    }

    // ── Network ───────────────────────────────────────────────────────────────
    if (cfg.includeNetwork) html += renderNetworkSection(data);

    // ── Malware ───────────────────────────────────────────────────────────────
    if (cfg.includeMalware) html += renderMalwareSection(data);

    // ── Event Logs ────────────────────────────────────────────────────────────
    if (cfg.includeEventLogs && data.contains("eventlogs")) {
        QJsonObject el = data["eventlogs"].toObject();
        QJsonObject sum = el["summary"].toObject();
        html += R"(<div class="section" id="eventlogs">
  <h2>Event Log Analysis</h2>
  <div class="alert alert-warning">
    <strong>⚠ Security Events Flagged:</strong> )" +
                QString::number(sum["flaggedEvents"].toInt()) + R"( events require investigation
  </div>
  <table class="data-table">
    <tr><th>Category</th><th>Count</th></tr>
    <tr><td>Total Events</td><td>)" + QString::number(sum["totalEvents"].toInt()) + R"(</td></tr>
    <tr><td>Failed Logins</td><td class="highlight-red">)" + QString::number(sum["failedLogins"].toInt()) + R"(</td></tr>
    <tr><td>Successful Logins</td><td>)" + QString::number(sum["successfulLogins"].toInt()) + R"(</td></tr>
    <tr><td>USB Events</td><td class="highlight-orange">)" + QString::number(sum["usbEvents"].toInt()) + R"(</td></tr>
    <tr><td>Process Executions</td><td>)" + QString::number(sum["processEvents"].toInt()) + R"(</td></tr>
    <tr><td>Application Crashes</td><td>)" + QString::number(sum["crashes"].toInt()) + R"(</td></tr>
    <tr><td>Security Events</td><td>)" + QString::number(sum["securityEvents"].toInt()) + R"(</td></tr>
  </table>
</div>)";
    }

    // ── AI Analysis ───────────────────────────────────────────────────────────
    if (cfg.includeAiSummary) html += renderAiSection(data);

    // ── Footer ────────────────────────────────────────────────────────────────
    html += R"(<div class="footer">
  <p>Generated by <strong>ForensicToolkit v1.0</strong> &mdash; )" +
            QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") +
            R"( &mdash; <em>)" + cfg.classificationLabel + R"(</em></p>
</div>
</body></html>)";

    return html;
}

QString ReportGenerator::renderEvidenceTable(const Forensic::Core::ForensicCase &c) const {
    QString html = R"(<div class="section" id="evidence">
  <h2>3. Evidence Inventory</h2>
  <table class="data-table">
    <tr><th>#</th><th>Label</th><th>Type</th><th>SHA-256</th><th>Size</th><th>Acquired</th><th>Verified</th></tr>)";
    int i = 1;
    for (const auto &ev : c.evidence) {
        html += QString("<tr><td>%1</td><td>%2</td><td>%3</td>"
                        "<td class=\"mono\">%4</td><td>%5 KB</td><td>%6</td>"
                        "<td>%7</td></tr>")
            .arg(i++).arg(ev.label.toHtmlEscaped(), ev.type.toHtmlEscaped())
            .arg(ev.hash.toHtmlEscaped())
            .arg(ev.sizeBytes / 1024)
            .arg(ev.acquiredAt.toString("yyyy-MM-dd"))
            .arg(ev.verified ? R"(<span class="badge badge-clean">✓ Verified</span>)"
                             : R"(<span class="badge badge-warning">Unverified</span>)");
    }
    html += R"(  </table>
</div>)";
    return html;
}

QString ReportGenerator::renderTimeline(const QJsonObject &data) const {
    QString html = R"(<div class="section" id="timeline">
  <h2>4. Investigation Timeline</h2>
  <div class="timeline">)";

    if (data.contains("timeline")) {
        QJsonArray events = data["timeline"].toArray();
        for (const auto &ev : events) {
            QJsonObject e = ev.toObject();
            html += QString(R"(<div class="timeline-event">
      <div class="timeline-time">%1</div>
      <div class="timeline-content">
        <strong>%2</strong><br>%3
      </div>
    </div>)")
                .arg(e["time"].toString(), e["title"].toString().toHtmlEscaped(),
                     e["description"].toString().toHtmlEscaped());
        }
    } else {
        html += R"(<p class="muted">No timeline events recorded.</p>)";
    }

    html += R"(  </div>
</div>)";
    return html;
}

QString ReportGenerator::renderNetworkSection(const QJsonObject &data) const {
    if (!data.contains("network")) return {};
    QJsonObject net = data["network"].toObject()["summary"].toObject();

    QString html = R"(<div class="section" id="network">
  <h2>Network Analysis</h2>
  <table class="data-table">
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Total Packets</td><td>)" + QString::number(net["totalPackets"].toInt()) + R"(</td></tr>
    <tr><td>TCP Packets</td><td>)" + QString::number(net["tcpPackets"].toInt()) + R"(</td></tr>
    <tr><td>UDP Packets</td><td>)" + QString::number(net["udpPackets"].toInt()) + R"(</td></tr>
    <tr><td>DNS Queries</td><td>)" + QString::number(net["dnsQueries"].toInt()) + R"(</td></tr>
    <tr><td>HTTP Requests</td><td>)" + QString::number(net["httpRequests"].toInt()) + R"(</td></tr>
    <tr><td>Suspicious Packets</td><td class="highlight-red">)" + QString::number(net["suspiciousPackets"].toInt()) + R"(</td></tr>
    <tr><td>Total Bytes</td><td>)" + QString::number(net["totalBytes"].toVariant().toLongLong() / 1024) + R"( KB</td></tr>
    <tr><td>Capture Start</td><td>)" + net["firstPacket"].toString() + R"(</td></tr>
    <tr><td>Capture End</td><td>)" + net["lastPacket"].toString() + R"(</td></tr>
  </table>
</div>)";
    return html;
}

QString ReportGenerator::renderMalwareSection(const QJsonObject &data) const {
    if (!data.contains("malware")) return {};
    QJsonObject mal = data["malware"].toObject();
    QJsonObject sum = mal["summary"].toObject();
    QJsonArray dets = mal["detections"].toArray();

    QString html = R"(<div class="section" id="malware">
  <h2>Malware Analysis</h2>)";

    if (sum["critical"].toInt() > 0 || sum["highThreat"].toInt() > 0) {
        html += R"(<div class="alert alert-danger">
    🚨 <strong>Critical threats detected!</strong> Immediate action required.
  </div>)";
    }

    html += R"(  <table class="data-table">
    <tr><th>Category</th><th>Count</th></tr>
    <tr><td>Total Scanned</td><td>)" + QString::number(sum["totalFiles"].toInt()) + R"(</td></tr>
    <tr><td>Clean</td><td class="highlight-green">)" + QString::number(sum["clean"].toInt()) + R"(</td></tr>
    <tr><td>Low Threat</td><td class="highlight-yellow">)" + QString::number(sum["lowThreat"].toInt()) + R"(</td></tr>
    <tr><td>Medium Threat</td><td class="highlight-orange">)" + QString::number(sum["mediumThreat"].toInt()) + R"(</td></tr>
    <tr><td>High Threat</td><td class="highlight-red">)" + QString::number(sum["highThreat"].toInt()) + R"(</td></tr>
    <tr><td>Critical</td><td class="highlight-red"><strong>)" + QString::number(sum["critical"].toInt()) + R"(</strong></td></tr>
  </table>)";

    if (!dets.isEmpty()) {
        html += R"(  <h3>Detections</h3>
  <table class="data-table">
    <tr><th>File</th><th>Verdict</th><th>SHA-256</th><th>Rules Matched</th></tr>)";
        for (const auto &d : dets) {
            QJsonObject det = d.toObject();
            html += QString("<tr><td>%1</td><td>%2</td><td class=\"mono\">%3</td><td>%4</td></tr>")
                .arg(det["filePath"].toString().toHtmlEscaped(),
                     det["verdict"].toString(),
                     det["sha256"].toString().left(16) + "...",
                     QString::number(det["matches"].toArray().size()));
        }
        html += "</table>";
    }

    html += "</div>";
    return html;
}

QString ReportGenerator::renderAiSection(const QJsonObject &data) const {
    if (!data.contains("aiAnalysis")) return {};
    QJsonObject ai = data["aiAnalysis"].toObject();

    QString html = R"(<div class="section" id="ai-analysis">
  <h2>AI Investigation Summary</h2>
  <div class="ai-badge">🤖 Generated by AI Assistant</div>)";

    auto section = [&](const QString &title, const QString &key) {
        QString text = ai[key].toString();
        if (!text.isEmpty()) {
            html += "<h3>" + title + "</h3><div class=\"ai-content\">"
                  + text.toHtmlEscaped().replace("\n", "<br>") + "</div>";
        }
    };

    section("Executive Summary",         "summary");
    section("Attack Timeline",           "attackTimeline");
    section("Indicators of Compromise",  "iocExplanation");
    section("Recommended Actions",       "recommendedActions");

    html += "</div>";
    return html;
}

QString ReportGenerator::cssStyles() const {
    return R"(
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #ffffff;
       color: #1a1a2e; font-size: 13px; line-height: 1.6; }
.cover-page { display: flex; flex-direction: column; justify-content: space-between;
              min-height: 100vh; padding: 0; text-align: center; }
.classification-banner { background: #c0392b; color: #fff; padding: 12px;
                          font-size: 16px; font-weight: bold; letter-spacing: 4px; }
.cover-content { padding: 60px 40px; }
.company-name { font-size: 28px; color: #2c3e50; font-weight: 300;
                letter-spacing: 2px; margin-bottom: 20px; text-transform: uppercase; }
.report-title { font-size: 36px; color: #1a1a2e; font-weight: 700;
                margin: 30px 0; border-top: 3px solid #3498db;
                border-bottom: 3px solid #3498db; padding: 20px 0; }
.case-title { font-size: 22px; color: #3498db; margin-bottom: 40px; }
.cover-table { margin: 0 auto; border-collapse: collapse; min-width: 400px; }
.cover-table td { padding: 10px 20px; border: 1px solid #ecf0f1; }
.cover-table td:first-child { background: #f8f9fa; font-weight: 600; }
.page-break { page-break-after: always; }
.section { padding: 30px 40px; margin-bottom: 20px; }
h2 { font-size: 22px; color: #2c3e50; border-left: 5px solid #3498db;
     padding-left: 15px; margin-bottom: 20px; }
h3 { font-size: 16px; color: #34495e; margin: 20px 0 10px; }
.data-table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 12px; }
.data-table th { background: #2c3e50; color: #ecf0f1; padding: 10px 12px;
                  text-align: left; font-weight: 600; }
.data-table td { padding: 8px 12px; border-bottom: 1px solid #ecf0f1; }
.data-table tr:nth-child(even) { background: #f8f9fa; }
.data-table tr:hover { background: #eaf4fb; }
.toc { padding-left: 30px; }
.toc li { padding: 5px 0; }
.toc a { color: #3498db; text-decoration: none; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 12px;
         font-size: 11px; font-weight: 600; }
.badge-clean { background: #27ae60; color: #fff; }
.badge-open  { background: #3498db; color: #fff; }
.badge-warning { background: #f39c12; color: #fff; }
.badge-in-progress { background: #8e44ad; color: #fff; }
.mono { font-family: 'Consolas', monospace; font-size: 11px; color: #555; }
.highlight-red    { color: #c0392b; font-weight: 600; }
.highlight-orange { color: #e67e22; font-weight: 600; }
.highlight-yellow { color: #f39c12; }
.highlight-green  { color: #27ae60; }
.alert { padding: 12px 18px; border-radius: 6px; margin: 15px 0; font-weight: 500; }
.alert-danger  { background: #fdf0f0; border-left: 5px solid #c0392b; color: #c0392b; }
.alert-warning { background: #fef9e7; border-left: 5px solid #f39c12; color: #856404; }
.timeline { padding-left: 20px; border-left: 3px solid #3498db; }
.timeline-event { margin: 15px 0; padding-left: 20px; position: relative; }
.timeline-event::before { content: '●'; position: absolute; left: -12px;
                           color: #3498db; font-size: 16px; }
.timeline-time { font-size: 11px; color: #7f8c8d; margin-bottom: 4px; }
.ai-badge { display: inline-block; background: #8e44ad; color: #fff;
            padding: 4px 14px; border-radius: 20px; font-size: 12px; margin-bottom: 15px; }
.ai-content { background: #f8f0ff; border-left: 4px solid #8e44ad;
              padding: 15px; border-radius: 0 8px 8px 0; line-height: 1.8; }
.muted { color: #95a5a6; font-style: italic; }
.footer { text-align: center; padding: 20px; border-top: 2px solid #ecf0f1;
          color: #7f8c8d; font-size: 11px; margin-top: 40px; }
)";
}

} // namespace Forensic::Modules
