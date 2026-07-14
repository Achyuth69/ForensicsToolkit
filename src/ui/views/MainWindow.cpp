#include "MainWindow.h"
#include "DashboardView.h"
#include "CaseManagerView.h"
#include "FileSystemView.h"
#include "FileIntegrityView.h"
#include "MemoryAnalysisView.h"
#include "NetworkForensicsView.h"
#include "EventLogView.h"
#include "MalwareView.h"
#include "AiAssistantView.h"
#include "ReportView.h"
#include "LogView.h"
#include "NewCaseDialog.h"
#include "SettingsDialog.h"
#include "CaseService.h"
#include "Logger.h"

#include <QApplication>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QSettings>
#include <QCloseEvent>
#include <QMessageBox>
#include <QFileDialog>
#include <QSplitter>
#include <QIcon>
#include <QFont>
#include <QDir>
#include <QFileInfo>
#include <QStyle>
#include <QStandardPaths>
#include <QLabel>

namespace Forensic::UI {

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    m_caseService = std::make_shared<Forensic::Services::CaseService>(this);
    QString dbPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                   + "/forensic.db";
    QDir().mkpath(QFileInfo(dbPath).absolutePath());
    m_caseService->openDatabase(dbPath);

    setupUi();
    setupMenuBar();
    setupToolBar();
    setupStatusBar();
    setupSystemTray();
    applyDarkTheme();
    loadSettings();

    LOG_INFO("ForensicToolkit v1.0.0 started");
    updateStatusBar("Ready — Forensic Investigation Toolkit v1.0");
}

MainWindow::~MainWindow() { saveSettings(); }

void MainWindow::setupUi()
{
    setWindowTitle("ForensicToolkit — Enterprise Digital Forensics Platform");
    setMinimumSize(1280, 800);
    resize(1600, 960);

    auto *central = new QWidget(this);
    setCentralWidget(central);
    auto *hlay = new QHBoxLayout(central);
    hlay->setContentsMargins(0, 0, 0, 0);
    hlay->setSpacing(0);

    m_mainSplitter = new QSplitter(Qt::Horizontal, central);
    m_mainSplitter->setHandleWidth(2);

    setupNavPanel();
    setupCentralArea();

    m_mainSplitter->addWidget(m_navTree);
    m_mainSplitter->addWidget(m_stack);
    m_mainSplitter->setStretchFactor(0, 0);
    m_mainSplitter->setStretchFactor(1, 1);
    m_mainSplitter->setSizes({220, 1380});

    hlay->addWidget(m_mainSplitter);
}

void MainWindow::setupNavPanel()
{
    m_navTree = new QTreeWidget(this);
    m_navTree->setHeaderHidden(true);
    m_navTree->setFixedWidth(222);
    m_navTree->setIndentation(14);
    m_navTree->setAnimated(true);

    struct NavEntry { QString text; int index; bool isGroup; };
    // Top-level items
    auto addTop = [&](const QString &text, int idx) {
        auto *item = new QTreeWidgetItem(m_navTree, {text});
        item->setData(0, Qt::UserRole, idx);
        return item;
    };
    auto addChild = [&](QTreeWidgetItem *parent, const QString &text, int idx) {
        auto *item = new QTreeWidgetItem(parent, {text});
        item->setData(0, Qt::UserRole, idx);
        return item;
    };

    addTop("  📊  Dashboard",         0);
    addTop("  📂  Case Management",   1);

    auto *analysis = addTop("  🔬  Analysis",   -1);
    analysis->setExpanded(true);
    addChild(analysis, "    🗂  File System",    2);
    addChild(analysis, "    🔒  File Integrity", 3);
    addChild(analysis, "    🧠  Memory",         4);
    addChild(analysis, "    🌐  Network",         5);
    addChild(analysis, "    📋  Event Logs",      6);

    auto *threats = addTop("  🛡  Threat Analysis", -1);
    threats->setExpanded(true);
    addChild(threats, "    🦠  Malware Scan",    7);
    addChild(threats, "    🤖  AI Assistant",    8);

    addTop("  📄  Reports",            9);
    addTop("  📝  System Log",        10);

    connect(m_navTree, &QTreeWidget::itemClicked, this, &MainWindow::onNavItemClicked);
}

void MainWindow::setupCentralArea()
{
    m_stack = new QStackedWidget(this);

    m_dashboard     = new DashboardView(m_stack);
    m_caseManager   = new CaseManagerView(m_caseService, m_stack);
    m_fsView        = new FileSystemView(m_stack);
    m_integrityView = new FileIntegrityView(m_stack);
    m_memView       = new MemoryAnalysisView(m_stack);
    m_netView       = new NetworkForensicsView(m_stack);
    m_evtView       = new EventLogView(m_stack);
    m_malwareView   = new MalwareView(m_stack);
    m_aiView        = new AiAssistantView(m_stack);
    m_reportView    = new ReportView(m_stack);
    m_logView       = new LogView(m_stack);

    m_stack->addWidget(m_dashboard);      // 0
    m_stack->addWidget(m_caseManager);    // 1
    m_stack->addWidget(m_fsView);         // 2
    m_stack->addWidget(m_integrityView);  // 3
    m_stack->addWidget(m_memView);        // 4
    m_stack->addWidget(m_netView);        // 5
    m_stack->addWidget(m_evtView);        // 6
    m_stack->addWidget(m_malwareView);    // 7
    m_stack->addWidget(m_aiView);         // 8
    m_stack->addWidget(m_reportView);     // 9
    m_stack->addWidget(m_logView);        // 10
}

void MainWindow::setupMenuBar()
{
    auto *fileMenu = menuBar()->addMenu("&File");
    fileMenu->addAction("&New Case",        this, &MainWindow::onNewCase,      QKeySequence::New);
    fileMenu->addAction("&Open Case",       this, &MainWindow::onOpenCase,     QKeySequence::Open);
    fileMenu->addSeparator();
    fileMenu->addAction("&Export Report",   this, &MainWindow::onExportReport);
    fileMenu->addSeparator();
    fileMenu->addAction("E&xit",            qApp, &QApplication::quit,         QKeySequence::Quit);

    auto *toolsMenu = menuBar()->addMenu("&Tools");
    toolsMenu->addAction("&Settings",       this, &MainWindow::onShowSettings);
    toolsMenu->addAction("&System Log",     this, &MainWindow::onToggleLog);

    auto *helpMenu = menuBar()->addMenu("&Help");
    helpMenu->addAction("&About",           this, &MainWindow::onShowAbout);
}

void MainWindow::setupToolBar()
{
    auto *tb = addToolBar("Main");
    tb->setMovable(false);
    tb->setIconSize(QSize(20, 20));
    tb->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);

    tb->addAction(style()->standardIcon(QStyle::SP_FileDialogNewFolder),
                  "New Case",  this, &MainWindow::onNewCase);
    tb->addAction(style()->standardIcon(QStyle::SP_DialogOpenButton),
                  "Open",      this, &MainWindow::onOpenCase);
    tb->addSeparator();
    tb->addAction(style()->standardIcon(QStyle::SP_FileIcon),
                  "Report",    this, &MainWindow::onExportReport);
    tb->addSeparator();
    tb->addAction(style()->standardIcon(QStyle::SP_ComputerIcon),
                  "Settings",  this, &MainWindow::onShowSettings);
}

void MainWindow::setupStatusBar()
{
    m_statusLabel = new QLabel("Ready", this);
    m_statusLabel->setMinimumWidth(300);

    m_statusProgress = new QProgressBar(this);
    m_statusProgress->setRange(0, 100);
    m_statusProgress->setFixedWidth(180);
    m_statusProgress->setVisible(false);

    statusBar()->addWidget(m_statusLabel, 1);
    statusBar()->addPermanentWidget(m_statusProgress);
    statusBar()->addPermanentWidget(new QLabel("  ForensicToolkit v1.0  ", this));
}

void MainWindow::setupSystemTray()
{
    m_trayIcon = new QSystemTrayIcon(
        style()->standardIcon(QStyle::SP_ComputerIcon), this);
    m_trayIcon->setToolTip("ForensicToolkit");
    m_trayIcon->show();
}

void MainWindow::applyDarkTheme()
{
    QFile qss(":/styles/dark.qss");
    if (qss.open(QIODevice::ReadOnly)) {
        qApp->setStyleSheet(QString::fromUtf8(qss.readAll()));
        return;
    }
    // Fallback: minimal inline dark palette
    qApp->setStyleSheet(R"(
QMainWindow,QWidget,QDialog{background:#1e1e2e;color:#cdd6f4;}
QMenuBar{background:#181825;color:#cdd6f4;border-bottom:1px solid #313244;}
QMenuBar::item:selected{background:#313244;}
QMenu{background:#1e1e2e;border:1px solid #45475a;}
QMenu::item:selected{background:#313244;color:#89b4fa;}
QToolBar{background:#181825;border-bottom:1px solid #313244;spacing:4px;}
QToolBar QToolButton{color:#cdd6f4;padding:5px 10px;border-radius:5px;}
QToolBar QToolButton:hover{background:#313244;}
QStatusBar{background:#181825;color:#a6adc8;border-top:1px solid #313244;}
QTreeWidget{background:#181825;border:none;color:#cdd6f4;outline:none;}
QTreeWidget::item{padding:7px 6px;border-radius:5px;margin:1px 4px;}
QTreeWidget::item:selected{background:#313244;color:#89b4fa;}
QTreeWidget::item:hover:!selected{background:#262637;}
QTabWidget::pane{border:1px solid #45475a;background:#1e1e2e;}
QTabBar::tab{background:#181825;color:#a6adc8;padding:8px 16px;border-bottom:2px solid transparent;}
QTabBar::tab:selected{color:#89b4fa;border-bottom:2px solid #89b4fa;}
QTableWidget,QTableView{background:#1e1e2e;gridline-color:#313244;color:#cdd6f4;border:none;}
QHeaderView::section{background:#181825;color:#89b4fa;padding:7px;border:none;border-bottom:2px solid #45475a;font-weight:bold;}
QLineEdit,QTextEdit,QPlainTextEdit{background:#313244;color:#cdd6f4;border:1px solid #45475a;border-radius:5px;padding:5px 8px;}
QLineEdit:focus,QTextEdit:focus{border-color:#89b4fa;}
QComboBox{background:#313244;color:#cdd6f4;border:1px solid #45475a;border-radius:5px;padding:5px 8px;}
QComboBox QAbstractItemView{background:#1e1e2e;border:1px solid #45475a;color:#cdd6f4;selection-background-color:#313244;}
QPushButton{background:#313244;color:#cdd6f4;border:1px solid #45475a;border-radius:6px;padding:6px 16px;font-weight:500;}
QPushButton:hover{background:#45475a;}
QPushButton:pressed{background:#585b70;}
QPushButton[primary="true"]{background:#89b4fa;color:#1e1e2e;border:none;font-weight:600;}
QPushButton[primary="true"]:hover{background:#b4d0ff;}
QPushButton[danger="true"]{background:#f38ba8;color:#1e1e2e;border:none;}
QProgressBar{background:#313244;border-radius:4px;border:none;}
QProgressBar::chunk{background:#89b4fa;border-radius:4px;}
QScrollBar:vertical{background:#1e1e2e;width:8px;}
QScrollBar::handle:vertical{background:#45475a;border-radius:4px;min-height:20px;}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}
QSplitter::handle{background:#313244;}
QGroupBox{border:1px solid #45475a;border-radius:7px;margin-top:10px;padding-top:8px;color:#89b4fa;}
QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 6px;background:#1e1e2e;}
QCheckBox{color:#cdd6f4;spacing:8px;}
QCheckBox::indicator{width:16px;height:16px;border:1px solid #585b70;border-radius:3px;background:#313244;}
QCheckBox::indicator:checked{background:#89b4fa;border-color:#89b4fa;}
QToolTip{background:#313244;color:#cdd6f4;border:1px solid #45475a;border-radius:4px;padding:4px 8px;}
    )");
}

void MainWindow::onNavItemClicked(QTreeWidgetItem *item, int)
{
    if (!item) return;
    int idx = item->data(0, Qt::UserRole).toInt();
    if (idx >= 0) switchToView(idx);
}

void MainWindow::switchToView(int index)
{
    m_stack->setCurrentIndex(index);
    if (index == 0) m_dashboard->refresh();
}

void MainWindow::onNewCase()
{
    switchToView(1);
    NewCaseDialog dlg(m_caseService, this);
    if (dlg.exec() == QDialog::Accepted)
        m_caseManager->refreshCaseList();
}

void MainWindow::onOpenCase()    { switchToView(1); }
void MainWindow::onExportReport(){ switchToView(9); }

void MainWindow::onShowSettings()
{
    SettingsDialog dlg(this);
    dlg.exec();
}

void MainWindow::onShowAbout()
{
    QMessageBox::about(this, "About ForensicToolkit",
        "<h2>ForensicToolkit v1.0.0</h2>"
        "<p>Enterprise Digital Forensics Investigation Platform</p>"
        "<p><b>Stack:</b> C++17 · Qt 6 · OpenSSL · SQLite</p>"
        "<p><b>Modules:</b> File System · Memory · Network · Event Logs<br>"
        "Malware Detection · AI Assistant · Report Generator</p>"
        "<hr><p style='color:#888'>Portfolio project — enterprise-grade software engineering.</p>");
}

void MainWindow::onToggleLog()    { switchToView(10); }

void MainWindow::updateStatusBar(const QString &msg)
{
    m_statusLabel->setText(msg);
}

void MainWindow::loadSettings()
{
    QSettings s("ForensicToolkit", "ForensicToolkit");
    restoreGeometry(s.value("geometry").toByteArray());
    restoreState(s.value("windowState").toByteArray());
}

void MainWindow::saveSettings()
{
    QSettings s("ForensicToolkit", "ForensicToolkit");
    s.setValue("geometry",    saveGeometry());
    s.setValue("windowState", saveState());
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    saveSettings();
    event->accept();
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
}

} // namespace Forensic::UI
