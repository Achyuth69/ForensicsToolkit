#pragma once
#include <QWidget>
#include <QFrame>
#include <QLabel>
#include <QMap>
#include <QDateTime>
#include <QtCharts/QChartView>

namespace Forensic::UI {

// ── MetricCard ────────────────────────────────────────────────────────────────
class MetricCard : public QFrame {
    Q_OBJECT
public:
    MetricCard(const QString &title, const QString &icon,
               const QString &color, QWidget *parent = nullptr);
    void setValue  (const QString &val);
    void setSubtext(const QString &s);

private:
    QLabel *m_valueLabel   {nullptr};
    QLabel *m_subtextLabel {nullptr};
};

// ── DashboardView ─────────────────────────────────────────────────────────────
class DashboardView : public QWidget {
    Q_OBJECT
public:
    explicit DashboardView(QWidget *parent = nullptr);

    void refresh();
    void setEvidenceCount  (int n);
    void setThreatScore    (int score);
    void setActiveCase     (const QString &caseName);
    void setNetworkAlerts  (int n);
    void setMalwareFindings(int n);
    void updateThreatChart   (const QMap<QString,int> &threats);
    void updateTimelineChart (const QList<QPair<QDateTime,int>> &events);

private:
    MetricCard *m_evidenceCard  {nullptr};
    MetricCard *m_threatCard    {nullptr};
    MetricCard *m_networkCard   {nullptr};
    MetricCard *m_malwareCard   {nullptr};
    QChartView *m_threatChart   {nullptr};
    QChartView *m_protocolChart {nullptr};
};

} // namespace Forensic::UI
