#pragma once
#include <QMainWindow>
#include <QStackedWidget>
#include <QTreeWidget>
#include <QSplitter>
#include <QLabel>
#include <QProgressBar>
#include <QSystemTrayIcon>
#include <memory>

// Forward-declare service
namespace Forensic::Services { class CaseService; }

// Forward-declare all view types — implementations in their own .cpp files
namespace Forensic::UI {
    class DashboardView;
    class CaseManagerView;
    class FileSystemView;
    class FileIntegrityView;
    class MemoryAnalysisView;
    class NetworkForensicsView;
    class EventLogView;
    class MalwareView;
    class AiAssistantView;
    class ReportView;
    class LogView;
}

namespace Forensic::UI {

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent (QCloseEvent  *event) override;
    void resizeEvent(QResizeEvent *event) override;

private slots:
    void onNavItemClicked(QTreeWidgetItem *item, int col);
    void onNewCase();
    void onOpenCase();
    void onExportReport();
    void onShowSettings();
    void onShowAbout();
    void onToggleLog();
    void updateStatusBar(const QString &msg);

private:
    void setupUi();
    void setupMenuBar();
    void setupToolBar();
    void setupNavPanel();
    void setupCentralArea();
    void setupStatusBar();
    void setupSystemTray();
    void applyDarkTheme();
    void loadSettings();
    void saveSettings();
    void switchToView(int index);

    // Layout
    QSplitter       *m_mainSplitter  {nullptr};
    QTreeWidget     *m_navTree       {nullptr};
    QStackedWidget  *m_stack         {nullptr};
    QLabel          *m_statusLabel   {nullptr};
    QProgressBar    *m_statusProgress{nullptr};
    QSystemTrayIcon *m_trayIcon      {nullptr};

    // Views  (indices 0-10 match m_stack order)
    DashboardView        *m_dashboard    {nullptr};
    CaseManagerView      *m_caseManager  {nullptr};
    FileSystemView       *m_fsView       {nullptr};
    FileIntegrityView    *m_integrityView{nullptr};
    MemoryAnalysisView   *m_memView      {nullptr};
    NetworkForensicsView *m_netView      {nullptr};
    EventLogView         *m_evtView      {nullptr};
    MalwareView          *m_malwareView  {nullptr};
    AiAssistantView      *m_aiView       {nullptr};
    ReportView           *m_reportView   {nullptr};
    LogView              *m_logView      {nullptr};

    std::shared_ptr<Forensic::Services::CaseService> m_caseService;
};

} // namespace Forensic::UI
