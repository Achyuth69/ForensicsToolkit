#include "Logger.h"
#include <QTextStream>
#include <QThread>
#include <QMutexLocker>
#include <iostream>

namespace Forensic::Core {

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

Logger::Logger() = default;

Logger::~Logger() {
    if (m_file.isOpen())
        m_file.close();
}

void Logger::setLogFile(const QString &path) {
    QMutexLocker lock(&m_mutex);
    if (m_file.isOpen()) m_file.close();
    m_file.setFileName(path);
    m_file.open(QIODevice::Append | QIODevice::Text);
}

void Logger::setMinLevel(LogLevel level) {
    QMutexLocker lock(&m_mutex);
    m_minLevel = level;
}

void Logger::addSink(std::function<void(const LogEntry&)> sink) {
    QMutexLocker lock(&m_mutex);
    m_sinks.push_back(std::move(sink));
}

void Logger::log(LogLevel level, const QString &msg, const QString &source) {
    if (level < m_minLevel) return;

    LogEntry entry;
    entry.level     = level;
    entry.message   = msg;
    entry.source    = source;
    entry.timestamp = QDateTime::currentDateTime();
    entry.threadId  = QString("0x%1").arg(
        reinterpret_cast<quintptr>(QThread::currentThreadId()), 8, 16, QLatin1Char('0'));

    QString line = QString("[%1] [%2] [%3] %4")
        .arg(entry.timestamp.toString("yyyy-MM-dd hh:mm:ss.zzz"))
        .arg(levelString(level), -8)
        .arg(source.isEmpty() ? "Core" : source)
        .arg(msg);

    {
        QMutexLocker lock(&m_mutex);
        if (m_file.isOpen()) {
            QTextStream ts(&m_file);
            ts << line << "\n";
            m_file.flush();
        }
        if (level >= LogLevel::Warning) {
            std::cerr << line.toStdString() << "\n";
        }
        for (auto &sink : m_sinks) {
            sink(entry);
        }
    }

    emit newEntry(entry);
}

void Logger::trace   (const QString &msg, const QString &src) { log(LogLevel::Trace,    msg, src); }
void Logger::debug   (const QString &msg, const QString &src) { log(LogLevel::Debug,    msg, src); }
void Logger::info    (const QString &msg, const QString &src) { log(LogLevel::Info,     msg, src); }
void Logger::warning (const QString &msg, const QString &src) { log(LogLevel::Warning,  msg, src); }
void Logger::error   (const QString &msg, const QString &src) { log(LogLevel::Error,    msg, src); }
void Logger::critical(const QString &msg, const QString &src) { log(LogLevel::Critical, msg, src); }

QString Logger::levelString(LogLevel l) {
    switch (l) {
    case LogLevel::Trace:    return "TRACE";
    case LogLevel::Debug:    return "DEBUG";
    case LogLevel::Info:     return "INFO";
    case LogLevel::Warning:  return "WARN";
    case LogLevel::Error:    return "ERROR";
    case LogLevel::Critical: return "CRIT";
    }
    return "UNKNOWN";
}

} // namespace Forensic::Core
