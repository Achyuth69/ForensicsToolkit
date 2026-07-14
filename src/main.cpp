#include <QApplication>
#include <QSplashScreen>
#include <QPixmap>
#include <QTimer>
#include <QDir>
#include <QStandardPaths>
#include <QStyleFactory>
#include <QFontDatabase>

#include "MainWindow.h"
#include "Logger.h"

int main(int argc, char *argv[]) {
    // High-DPI support
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling, true);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps,   true);

    QApplication app(argc, argv);
    app.setApplicationName("ForensicToolkit");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("ForensicToolkit");
    app.setOrganizationDomain("forensictoolkit.local");
    app.setStyle(QStyleFactory::create("Fusion"));

    // ── Application data directory ─────────────────────────────────────────
    QString appData = QStandardPaths::writableLocation(
        QStandardPaths::AppDataLocation);
    QDir().mkpath(appData);

    // ── Logging setup ─────────────────────────────────────────────────────
    QString logPath = appData + "/forensic.log";
    Forensic::Core::Logger::instance().setLogFile(logPath);
    Forensic::Core::Logger::instance().setMinLevel(Forensic::Core::LogLevel::Info);
    Forensic::Core::Logger::instance().info("ForensicToolkit v1.0.0 starting", "main");

    // ── Splash screen ─────────────────────────────────────────────────────
    QSplashScreen *splash = nullptr;
    QPixmap splashPix(":/icons/splash.png");
    if (!splashPix.isNull()) {
        splash = new QSplashScreen(splashPix);
        splash->show();
        splash->showMessage("Loading ForensicToolkit v1.0.0...",
                            Qt::AlignBottom | Qt::AlignHCenter,
                            Qt::white);
        app.processEvents();
    }

    // ── Main window ───────────────────────────────────────────────────────
    Forensic::UI::MainWindow window;
    window.show();

    if (splash) {
        QTimer::singleShot(1500, splash, [splash, &window]{
            splash->finish(&window);
            splash->deleteLater();
        });
    }

    Forensic::Core::Logger::instance().info("Main window displayed", "main");
    return app.exec();
}
