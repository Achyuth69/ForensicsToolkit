#pragma once
#include <QObject>
#include <QString>
#include <QList>
#include <QJsonObject>
#include <atomic>

namespace Forensic::Modules {

struct ProcessEntry {
    quint64  pid{0};
    quint64  ppid{0};
    QString  name;
    QString  path;
    QString  commandLine;
    QString  user;
    quint64  baseAddress{0};
    quint64  memorySize{0};
    bool     isSuspicious{false};
    QString  suspicionReason;
    QList<QString> loadedDlls;
    QList<QString> networkConnections;
};

struct StringEntry {
    quint64 offset{0};
    QString value;
    bool    isPrintable{true};
    int     length{0};
};

struct NetworkConnection {
    QString protocol;
    QString localIp;
    quint16 localPort{0};
    QString remoteIp;
    quint16 remotePort{0};
    QString state;
    quint64 pid{0};
    QString processName;
};

struct MemoryAnalysisResult {
    QString                   imagePath;
    quint64                   imageSize{0};
    QList<ProcessEntry>       processes;
    QList<StringEntry>        strings;
    QList<NetworkConnection>  networkConnections;
    QList<QString>            loadedModules;
    QList<ProcessEntry>       suspiciousProcesses;
    bool                      analysisComplete{false};
};

class MemoryAnalyzer : public QObject {
    Q_OBJECT
public:
    explicit MemoryAnalyzer(QObject *parent = nullptr);

    void analyzeImage(const QString &imagePath);
    void cancel();

    const MemoryAnalysisResult& result() const { return m_result; }
    QJsonObject toJson() const;

signals:
    void progressChanged(int percent, const QString &stage);
    void analysisComplete(const MemoryAnalysisResult &result);
    void errorOccurred(const QString &error);

private:
    void extractStrings(const QByteArray &data);
    void parseProcessList(const QByteArray &data);
    void parseNetworkConnections(const QByteArray &data);
    bool isSuspiciousProcess(const ProcessEntry &pe);

    MemoryAnalysisResult m_result;
    std::atomic<bool>    m_cancelled{false};
};

} // namespace Forensic::Modules
