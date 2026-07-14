#include "NetworkForensicsView.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QFile>
#include <QPainter>
#include <QtConcurrent/QtConcurrent>
#include <QtCharts/QChart>
#include <QtCharts/QPieSeries>
#include <QtCharts/QBarSeries>
#include <QtCharts/QBarSet>
#include <QtCharts/QBarCategoryAxis>

namespace Forensic::UI {

NetworkForensicsView::NetworkForensicsView(QWidget *parent) : QWidget(parent) {
    m_analyzer = std::make_unique<Forensic::Modules::NetworkForensics>(this);
    connect(m_analyzer.get(), &Forensic::Modules::NetworkForensics::progressChanged,
            this, &NetworkForensicsView::onProgress);
    connect(m_analyzer.get(), &Forensic::Modules::NetworkForensics::analysisComplete,
            this, &NetworkForensicsView::onAnalysisComplete);
    connect(m_analyzer.get(), &Forensic::Modules::NetworkForensics::errorOccurred,
            this, [this](const QString &e){ QMessageBox::critical(this,"Error",e); });
    setupUi();
}

void NetworkForensicsView::setupUi() {
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0,0,0,0);

    auto *header = new QWidget(this);
    header->setStyleSheet("background:#181825;border-bottom:1px solid #45475a;");
    auto *hl = new QHBoxLayout(header);
    hl->setContentsMargins(16,10,16,10);
    auto *title = new QLabel("🌐  Network Forensics", header);
    title->setStyleSheet("font-size:16px;font-weight:bold;color:#89b4fa;");
    hl->addWidget(title);
    layout->addWidget(header);

    auto *tb = new QWidget(this);
    tb->setStyleSheet("background:#262637;border-bottom:1px solid #45475a;");
    auto *tl = new QHBoxLayout(tb);
    tl->setContentsMargins(12,8,12,8);

    auto *pcapEdit   = new QLineEdit(tb);
    pcapEdit->setPlaceholderText("PCAP file path...");
    auto *browseBtn  = new QPushButton("Browse...", tb);
    auto *loadBtn    = new QPushButton("▶ Load & Analyze", tb);
    auto *exportBtn  = new QPushButton("Export JSON", tb);
    loadBtn->setProperty("primary",true);

    connect(browseBtn, &QPushButton::clicked, this, [this, pcapEdit]{
        QString f = QFileDialog::getOpenFileName(this,"Open PCAP","",
            "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)");
        if (!f.isEmpty()) pcapEdit->setText(f);
    });
    connect(loadBtn, &QPushButton::clicked, this, [this, pcapEdit]{
        QString p = pcapEdit->text().trimmed();
        if (p.isEmpty()){ QMessageBox::warning(this,"No File","Select a PCAP file."); return; }
        m_progress->setVisible(true);
        m_packetTable->setRowCount(0);
        m_dnsTable->setRowCount(0);
        m_httpTable->setRowCount(0);
        m_statusLabel->setText("Loading PCAP...");
        QtConcurrent::run([this, p]{ m_analyzer->loadPcap(p); });
    });
    connect(exportBtn, &QPushButton::clicked, this, &NetworkForensicsView::onExport);

    tl->addWidget(pcapEdit,1);
    tl->addWidget(browseBtn);
    tl->addWidget(loadBtn);
    tl->addStretch();
    tl->addWidget(exportBtn);
    layout->addWidget(tb);

    m_progress = new QProgressBar(this);
    m_progress->setRange(0,100);
    m_progress->setVisible(false);
    m_progress->setFixedHeight(6);
    layout->addWidget(m_progress);

    m_statusLabel = new QLabel("Load a PCAP file to begin analysis",this);
    m_statusLabel->setStyleSheet("padding:4px 16px;color:#a6adc8;font-size:12px;");
    layout->addWidget(m_statusLabel);

    m_tabs = new QTabWidget(this);
    setupPacketTable();
    setupSummaryTab();
    setupDnsTab();
    setupHttpTab();
    layout->addWidget(m_tabs,1);
}

void NetworkForensicsView::setupPacketTable() {
    auto *tab = new QWidget(m_tabs);
    auto *l = new QVBoxLayout(tab);
    l->setContentsMargins(0,0,0,0);
    m_packetTable = new QTableWidget(0,7,tab);
    m_packetTable->setHorizontalHeaderLabels(
        {"#","Time","Protocol","Src IP","Src Port","Dst IP","Dst Port"});
    m_packetTable->horizontalHeader()->setSectionResizeMode(1,QHeaderView::ResizeToContents);
    m_packetTable->horizontalHeader()->setSectionResizeMode(2,QHeaderView::ResizeToContents);
    m_packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_packetTable->verticalHeader()->setVisible(false);
    m_packetTable->setAlternatingRowColors(true);
    m_packetTable->setSortingEnabled(false);
    connect(m_packetTable, &QTableWidget::cellClicked,
            this, &NetworkForensicsView::onPacketSelected);
    l->addWidget(m_packetTable);
    m_tabs->addTab(tab,"Packets");
}

void NetworkForensicsView::setupSummaryTab() {
    auto *tab = new QWidget(m_tabs);
    auto *l = new QHBoxLayout(tab);

    auto *summaryWidget = new QWidget(tab);
    auto *sl = new QVBoxLayout(summaryWidget);
    auto *sumLabel = new QLabel("Summary Statistics",summaryWidget);
    sumLabel->setStyleSheet("font-size:14px;font-weight:bold;color:#89b4fa;padding-bottom:8px;");
    sl->addWidget(sumLabel);

    // Stats table
    auto *statsTable = new QTableWidget(0,2,summaryWidget);
    statsTable->setObjectName("SummaryTable");
    statsTable->setHorizontalHeaderLabels({"Metric","Value"});
    statsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    statsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    statsTable->verticalHeader()->setVisible(false);
    statsTable->setObjectName("netSummaryTable");
    sl->addWidget(statsTable,1);
    l->addWidget(summaryWidget,1);

    // Protocol pie chart
    auto *pieSeries = new QPieSeries(tab);
    auto *chart = new QChart();
    chart->addSeries(pieSeries);
    chart->setTitle("Protocol Distribution");
    chart->setBackgroundBrush(QColor("#262637"));
    chart->setTitleBrush(QBrush(QColor("#cdd6f4")));
    chart->legend()->setLabelColor(QColor("#cdd6f4"));
    m_protocolChart = new QChartView(chart,tab);
    m_protocolChart->setRenderHint(QPainter::Antialiasing);
    m_protocolChart->setMinimumWidth(300);
    m_protocolChart->setStyleSheet("background:#262637;border-radius:8px;");
    l->addWidget(m_protocolChart,1);

    m_tabs->addTab(tab,"Summary");
}

void NetworkForensicsView::setupDnsTab() {
    auto *tab = new QWidget(m_tabs);
    auto *l = new QVBoxLayout(tab);
    l->setContentsMargins(0,0,0,0);
    m_dnsTable = new QTableWidget(0,4,tab);
    m_dnsTable->setHorizontalHeaderLabels({"Query","Response","Type","Source IP"});
    m_dnsTable->horizontalHeader()->setSectionResizeMode(0,QHeaderView::Stretch);
    m_dnsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_dnsTable->verticalHeader()->setVisible(false);
    m_dnsTable->setAlternatingRowColors(true);
    l->addWidget(m_dnsTable);
    m_tabs->addTab(tab,"DNS");
}

void NetworkForensicsView::setupHttpTab() {
    auto *tab = new QWidget(m_tabs);
    auto *l = new QVBoxLayout(tab);
    l->setContentsMargins(0,0,0,0);
    m_httpTable = new QTableWidget(0,5,tab);
    m_httpTable->setHorizontalHeaderLabels({"Method","URL","Host","Status","Src IP"});
    m_httpTable->horizontalHeader()->setSectionResizeMode(1,QHeaderView::Stretch);
    m_httpTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_httpTable->verticalHeader()->setVisible(false);
    m_httpTable->setAlternatingRowColors(true);
    l->addWidget(m_httpTable);
    m_tabs->addTab(tab,"HTTP");
}

void NetworkForensicsView::onProgress(int p, const QString &s) {
    m_progress->setValue(p);
    m_statusLabel->setText(s);
    if (p >= 100) m_progress->setVisible(false);
}

void NetworkForensicsView::onAnalysisComplete(const Forensic::Modules::NetworkSummary &s) {
    m_progress->setVisible(false);
    populateSummary(s);
    populatePackets(m_analyzer->packets());
    populateDns(m_analyzer->dnsRecords());
    populateHttp(m_analyzer->httpSessions());

    m_statusLabel->setText(
        QString("✔ %1 packets | TCP: %2 | UDP: %3 | DNS: %4 | HTTP: %5 | Suspicious: %6")
        .arg(s.totalPackets).arg(s.tcpPackets).arg(s.udpPackets)
        .arg(s.dnsQueries).arg(s.httpRequests).arg(s.suspiciousPackets));

    m_tabs->setTabText(0, QString("Packets (%1)").arg(m_analyzer->packets().size()));
    m_tabs->setTabText(2, QString("DNS (%1)").arg(m_analyzer->dnsRecords().size()));
    m_tabs->setTabText(3, QString("HTTP (%1)").arg(m_analyzer->httpSessions().size()));
}

void NetworkForensicsView::populatePackets(const QList<Forensic::Modules::Packet> &pkts) {
    int limit = qMin(10000, pkts.size());
    m_packetTable->setRowCount(limit);
    for (int i = 0; i < limit; i++) {
        const auto &p = pkts[i];
        m_packetTable->setItem(i,0,new QTableWidgetItem(QString::number(p.number)));
        m_packetTable->setItem(i,1,new QTableWidgetItem(
            p.timestamp.toString("hh:mm:ss.zzz")));
        QString proto;
        switch(p.protocol){
        case Forensic::Modules::Protocol::TCP:   proto="TCP";   break;
        case Forensic::Modules::Protocol::UDP:   proto="UDP";   break;
        case Forensic::Modules::Protocol::DNS:   proto="DNS";   break;
        case Forensic::Modules::Protocol::HTTP:  proto="HTTP";  break;
        case Forensic::Modules::Protocol::HTTPS: proto="HTTPS"; break;
        case Forensic::Modules::Protocol::SMTP:  proto="SMTP";  break;
        case Forensic::Modules::Protocol::FTP:   proto="FTP";   break;
        default:                                  proto="OTHER"; break;
        }
        m_packetTable->setItem(i,2,new QTableWidgetItem(proto));
        m_packetTable->setItem(i,3,new QTableWidgetItem(p.srcIp));
        m_packetTable->setItem(i,4,new QTableWidgetItem(QString::number(p.srcPort)));
        m_packetTable->setItem(i,5,new QTableWidgetItem(p.dstIp));
        m_packetTable->setItem(i,6,new QTableWidgetItem(QString::number(p.dstPort)));
        if (p.isSuspicious)
            for(int c=0;c<7;c++)
                if(m_packetTable->item(i,c))
                    m_packetTable->item(i,c)->setBackground(QColor("#3d1515"));
    }
}

void NetworkForensicsView::populateSummary(const Forensic::Modules::NetworkSummary &s) {
    // Find the stats table in the summary tab
    auto *tab = m_tabs->widget(1);
    auto *st  = tab->findChild<QTableWidget*>("netSummaryTable");
    if (!st) return;

    QList<QPair<QString,QString>> rows = {
        {"Total Packets",    QString::number(s.totalPackets)},
        {"TCP Packets",      QString::number(s.tcpPackets)},
        {"UDP Packets",      QString::number(s.udpPackets)},
        {"DNS Queries",      QString::number(s.dnsQueries)},
        {"HTTP Requests",    QString::number(s.httpRequests)},
        {"Suspicious",       QString::number(s.suspiciousPackets)},
        {"Total Bytes",      QString::number(s.totalBytes/1024)+" KB"},
        {"Capture Start",    s.firstPacket.toString("yyyy-MM-dd hh:mm:ss")},
        {"Capture End",      s.lastPacket.toString("yyyy-MM-dd hh:mm:ss")},
    };

    // Top IPs
    for (auto it = s.topDstIps.begin(); it != s.topDstIps.end(); ++it)
        rows.append({"Top Dst: "+it.key(), QString::number(it.value())+" pkts"});

    st->setRowCount(rows.size());
    for (int i = 0; i < rows.size(); i++) {
        st->setItem(i,0,new QTableWidgetItem(rows[i].first));
        st->setItem(i,1,new QTableWidgetItem(rows[i].second));
    }

    // Update pie chart
    auto *chart = m_protocolChart->chart();
    chart->removeAllSeries();
    auto *pie = new QPieSeries(this);
    if (s.tcpPackets)  pie->append("TCP",   s.tcpPackets);
    if (s.udpPackets)  pie->append("UDP",   s.udpPackets);
    if (s.dnsQueries)  pie->append("DNS",   s.dnsQueries);
    if (s.httpRequests)pie->append("HTTP",  s.httpRequests);
    chart->addSeries(pie);
}

void NetworkForensicsView::populateDns(const QList<Forensic::Modules::DnsRecord> &dns) {
    m_dnsTable->setRowCount(dns.size());
    for (int i = 0; i < dns.size(); i++) {
        m_dnsTable->setItem(i,0,new QTableWidgetItem(dns[i].query));
        m_dnsTable->setItem(i,1,new QTableWidgetItem(dns[i].response));
        m_dnsTable->setItem(i,2,new QTableWidgetItem(dns[i].type));
        m_dnsTable->setItem(i,3,new QTableWidgetItem(dns[i].srcIp));
    }
}

void NetworkForensicsView::populateHttp(const QList<Forensic::Modules::HttpSession> &http) {
    m_httpTable->setRowCount(http.size());
    for (int i = 0; i < http.size(); i++) {
        m_httpTable->setItem(i,0,new QTableWidgetItem(http[i].method));
        m_httpTable->setItem(i,1,new QTableWidgetItem(http[i].url));
        m_httpTable->setItem(i,2,new QTableWidgetItem(http[i].host));
        m_httpTable->setItem(i,3,new QTableWidgetItem(QString::number(http[i].statusCode)));
        m_httpTable->setItem(i,4,new QTableWidgetItem(http[i].srcIp));
    }
}

void NetworkForensicsView::onFilterApply() {}

void NetworkForensicsView::onExport() {
    QString path = QFileDialog::getSaveFileName(this,"Export JSON","","JSON (*.json)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (f.open(QIODevice::WriteOnly))
        f.write(QJsonDocument(m_analyzer->toJson()).toJson(QJsonDocument::Indented));
}

void NetworkForensicsView::onPacketSelected(int, int) {}

} // namespace Forensic::UI
