#include "DashboardView.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QFont>
#include <QPainter>
#include <QtCharts/QChart>
#include <QtCharts/QPieSeries>
#include <QtCharts/QBarSeries>
#include <QtCharts/QBarSet>
#include <QtCharts/QBarCategoryAxis>
#include <QtCharts/QValueAxis>
#include <QDateTime>

namespace Forensic::UI {

// ─── MetricCard ───────────────────────────────────────────────────────────────
MetricCard::MetricCard(const QString &title, const QString &icon,
                       const QString &color, QWidget *parent)
    : QFrame(parent)
{
    setObjectName("MetricCard");
    setMinimumSize(190, 115);
    setStyleSheet(QString(
        "#MetricCard {"
        "  background: #262637;"
        "  border-radius: 10px;"
        "  border-left: 4px solid %1;"
        "}").arg(color));

    auto *lay = new QVBoxLayout(this);
    lay->setContentsMargins(16, 14, 16, 14);
    lay->setSpacing(4);

    auto *topLabel = new QLabel(icon + "  " + title, this);
    topLabel->setStyleSheet("color:#a6adc8; font-size:12px; font-weight:500;");

    m_valueLabel = new QLabel("—", this);
    m_valueLabel->setStyleSheet(
        QString("color:%1; font-size:30px; font-weight:700;").arg(color));

    m_subtextLabel = new QLabel("", this);
    m_subtextLabel->setStyleSheet("color:#6c7086; font-size:11px;");

    lay->addWidget(topLabel);
    lay->addWidget(m_valueLabel);
    lay->addWidget(m_subtextLabel);
}

void MetricCard::setValue(const QString &val)  { m_valueLabel->setText(val);   }
void MetricCard::setSubtext(const QString &s)  { m_subtextLabel->setText(s);   }

// ─── DashboardView ────────────────────────────────────────────────────────────
DashboardView::DashboardView(QWidget *parent) : QWidget(parent)
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(24, 20, 24, 20);
    root->setSpacing(20);

    // ── Page title ────────────────────────────────────────────────────────
    auto *pageTitle = new QLabel("🔍  Investigation Dashboard", this);
    pageTitle->setStyleSheet("font-size:22px; font-weight:bold; color:#89b4fa;");
    root->addWidget(pageTitle);

    // ── Metric cards row ──────────────────────────────────────────────────
    m_evidenceCard = new MetricCard("Evidence Items", "📁", "#89b4fa", this);
    m_threatCard   = new MetricCard("Threat Score",   "⚠",  "#f38ba8", this);
    m_networkCard  = new MetricCard("Network Alerts", "🌐", "#fab387", this);
    m_malwareCard  = new MetricCard("Malware Hits",   "🦠", "#f38ba8", this);

    m_evidenceCard->setSubtext("Across all cases");
    m_threatCard->setSubtext("Overall risk level");
    m_networkCard->setSubtext("Suspicious packets");
    m_malwareCard->setSubtext("Detected threats");

    auto *cardsRow = new QHBoxLayout();
    cardsRow->setSpacing(16);
    cardsRow->addWidget(m_evidenceCard);
    cardsRow->addWidget(m_threatCard);
    cardsRow->addWidget(m_networkCard);
    cardsRow->addWidget(m_malwareCard);
    root->addLayout(cardsRow);

    // ── Charts row ────────────────────────────────────────────────────────
    auto *chartsRow = new QHBoxLayout();
    chartsRow->setSpacing(16);

    // Threat pie chart
    auto *pieSeries = new QPieSeries(this);
    pieSeries->append("Clean",    75)->setColor(QColor("#a6e3a1"));
    pieSeries->append("Low",      12)->setColor(QColor("#f9e2af"));
    pieSeries->append("Medium",    8)->setColor(QColor("#fab387"));
    pieSeries->append("High",      3)->setColor(QColor("#f38ba8"));
    pieSeries->append("Critical",  2)->setColor(QColor("#d20f39"));
    for (auto *s : pieSeries->slices()) s->setLabelVisible(false);

    auto *pieChart = new QChart();
    pieChart->addSeries(pieSeries);
    pieChart->setTitle("Threat Distribution");
    pieChart->setBackgroundBrush(QColor("#262637"));
    pieChart->setTitleBrush(QBrush(QColor("#cdd6f4")));
    pieChart->legend()->setLabelColor(QColor("#a6adc8"));
    pieChart->setAnimationOptions(QChart::AllAnimations);
    pieChart->setMargins(QMargins(0, 0, 0, 0));

    m_threatChart = new QChartView(pieChart, this);
    m_threatChart->setRenderHint(QPainter::Antialiasing);
    m_threatChart->setMinimumHeight(280);
    m_threatChart->setStyleSheet("background:#262637; border-radius:10px;");
    chartsRow->addWidget(m_threatChart, 1);

    // Protocol bar chart
    auto *barSet = new QBarSet("Packets", this);
    *barSet << 1250 << 430 << 87 << 210 << 55 << 12;
    barSet->setColor(QColor("#89b4fa"));

    auto *barSeries = new QBarSeries(this);
    barSeries->append(barSet);

    auto *barChart = new QChart();
    barChart->addSeries(barSeries);
    barChart->setTitle("Network Protocol Distribution");
    barChart->setBackgroundBrush(QColor("#262637"));
    barChart->setTitleBrush(QBrush(QColor("#cdd6f4")));
    barChart->legend()->hide();
    barChart->setAnimationOptions(QChart::SeriesAnimations);
    barChart->setMargins(QMargins(0, 0, 0, 0));

    auto *cats = new QBarCategoryAxis(this);
    cats->append({"TCP", "UDP", "DNS", "HTTP", "HTTPS", "SMTP"});
    cats->setLabelsColor(QColor("#a6adc8"));
    barChart->addAxis(cats, Qt::AlignBottom);
    barSeries->attachAxis(cats);

    auto *vAxis = new QValueAxis(this);
    vAxis->setLabelsColor(QColor("#a6adc8"));
    vAxis->setGridLineColor(QColor("#313244"));
    barChart->addAxis(vAxis, Qt::AlignLeft);
    barSeries->attachAxis(vAxis);

    m_protocolChart = new QChartView(barChart, this);
    m_protocolChart->setRenderHint(QPainter::Antialiasing);
    m_protocolChart->setMinimumHeight(280);
    m_protocolChart->setStyleSheet("background:#262637; border-radius:10px;");
    chartsRow->addWidget(m_protocolChart, 1);

    root->addLayout(chartsRow);
    root->addStretch();
}

void DashboardView::refresh() {}

void DashboardView::setEvidenceCount(int n) {
    m_evidenceCard->setValue(QString::number(n));
}

void DashboardView::setThreatScore(int score) {
    QString lbl = score < 30 ? "LOW" : score < 70 ? "MEDIUM" : "HIGH";
    m_threatCard->setValue(lbl);
    m_threatCard->setSubtext(QString("Score: %1 / 100").arg(score));
}

void DashboardView::setActiveCase(const QString &) {}

void DashboardView::setNetworkAlerts(int n) {
    m_networkCard->setValue(QString::number(n));
}

void DashboardView::setMalwareFindings(int n) {
    m_malwareCard->setValue(QString::number(n));
}

void DashboardView::updateThreatChart(const QMap<QString,int> &) {}
void DashboardView::updateTimelineChart(const QList<QPair<QDateTime,int>> &) {}

} // namespace Forensic::UI
