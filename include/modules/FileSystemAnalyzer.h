#pragma once
#include <QObject>
#include <QString>
#include <QDateTime>
#include <QList>
#include <QJsonObject>
#include <atomic>

namespace Forensic::Modules {

struct FileEntry {
    QString   path;
    QString   name;
    qint64    size{0};
    QString   extension;
    QDateTime created;
    QDateTime modified;
    QDateTime accessed;
    QString   sha256;
    QString   md5;
    bool      isHidden{false};
    bool      isSystem{false};
    bool      isDeleted{false};
    bool      isSymlink{false};
    QString   owner;
    uint      permissions{0};
    QString   mimeType;
};

struct ScanSummary {
    int    totalFiles{0};
    int    totalDirs{0};
    int    hiddenFiles{0};
    int    deletedFiles{0};
    int    duplicates{0};
    int    suspiciousFiles{0};
    qint64 totalSize{0};
};

class FileSystemAnalyzer : public QObject {
    Q_OBJECT
public:
    explicit FileSystemAnalyzer(QObject *parent = nullptr);
    ~FileSystemAnalyzer() override;

    void scanDirectory(const QString &rootPath, bool recursive = true,
                       bool computeHashes = true);
    void cancel();

    const QList<FileEntry>& results()    const { return m_results; }
    const ScanSummary&      summary()    const { return m_summary; }
    QList<FileEntry>        duplicates() const;
    QList<FileEntry>        hiddenFiles() const;
    QJsonObject             toJson()     const;

signals:
    void progressChanged(int percent, const QString &currentPath);
    void scanComplete(const ScanSummary &summary);
    void errorOccurred(const QString &error);
    void fileFound(const FileEntry &entry);

private:
    void scanRecursive(const QString &path);
    QString detectMimeType(const QString &path);

    QList<FileEntry>    m_results;
    ScanSummary         m_summary;
    std::atomic<bool>   m_cancelled{false};
    bool                m_computeHashes{true};
};

} // namespace Forensic::Modules
