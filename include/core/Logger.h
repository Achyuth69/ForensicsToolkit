#pragma once
#include <QObject>
#include <QString>
#include <QFile>
#include <QMutex>
#include <QDateTime>
#include <functional>

namespace Forensic::Core {

enum class LogLevel { Trace, Debug, Info, Warning, Error, Critical };

struct LogEntry {
    LogLevel  level;
    QString   message;
    QString   source;
    QDateTime timestamp;
    QString   threadId;
};

class Logger : public QObject {
    Q_OBJECT
public:
    static Logger& instance();

    void setLogFile(const QString &path);
    void setMinLevel(LogLevel level);
    void addSink(std::function<void(const LogEntry&)> sink);

    void log(LogLevel level, const QString &msg, const QString &source = {});
    void trace   (const QString &msg, const QString &src = {});
    void debug   (const QString &msg, const QString &src = {});
    void info    (const QString &msg, const QString &src = {});
    void warning (const QString &msg, const QString &src = {});
    void error   (const QString &msg, const QString &src = {});
    void critical(const QString &msg, const QString &src = {});

    static QString levelString(LogLevel l);

signals:
    void newEntry(const LogEntry &entry);

private:
    Logger();
    ~Logger();

    QMutex   m_mutex;
    QFile    m_file;
    LogLevel m_minLevel{LogLevel::Info};
    std::vector<std::function<void(const LogEntry&)>> m_sinks;
};

} // namespace Forensic::Core

// Convenience macros
#define LOG_INFO(msg)    Forensic::Core::Logger::instance().info(msg,    __FUNCTION__)
#define LOG_WARN(msg)    Forensic::Core::Logger::instance().warning(msg, __FUNCTION__)
#define LOG_ERROR(msg)   Forensic::Core::Logger::instance().error(msg,   __FUNCTION__)
#define LOG_DEBUG(msg)   Forensic::Core::Logger::instance().debug(msg,   __FUNCTION__)
#define LOG_CRITICAL(msg) Forensic::Core::Logger::instance().critical(msg, __FUNCTION__)
