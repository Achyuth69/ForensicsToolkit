#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QTabWidget>
#include <QProgressBar>
#include <QLabel>
#include <QPainter>
#include <memory>
#include <QtCharts/QChartView>
#include "NetworkForensics.h"

namespace Forensic::UI {

class NetworkForensicsView : public QWidget {
    Q_OBJECT
public:
    explicit NetworkForensicsView(QWidget *parent = nullptr);

private slots:
    void onProgress       (int pct, const QString &stage);
    void onAnalysisComplete(const Forensic::Modules::NetworkSummary &summary);
    void onFilterApply();
    void onExport();
    void onPacketSelected(int row, int col);

private:
    void setupUi();
    void setupPacketTable();
    void setupSummaryTab();
    void setupDnsTab();
    void setupHttpTab();
    void populatePackets(const QList<Forensic::Modules::Packet>      &pkts);
    void populateSummary(const Forensic::Modules::NetworkSummary     &s);
    void populateDns    (const QList<Forensic::Modules::DnsRecord>   &dns);
    void populateHttp   (const QList<Forensic::Modules::HttpSession> &http);

    QTabWidget   *m_tabs          {nullptr};
    QTableWidget *m_packetTable   {nullptr};
    QTableWidget *m_dnsTable      {nullptr};
    QTableWidget *m_httpTable     {nullptr};
    QProgressBar *m_progress      {nullptr};
    QLabel       *m_statusLabel   {nullptr};
    QChartView   *m_protocolChart {nullptr};
    QChartView   *m_topIpChart    {nullptr};

    std::unique_ptr<Forensic::Modules::NetworkForensics> m_analyzer;
};

} // namespace Forensic::UI
