#include "FileSystemAnalyzer.h"
#include "HashEngine.h"
#include "Logger.h"
#include <QDir>
#include <QFileInfo>
#include <QFileInfoList>
#include <QJsonArray>
#include <QJsonObject>
#include <QMimeDatabase>
#include <QThread>
#ifdef Q_OS_WIN
#  include <windows.h>
#endif

namespace Forensic::Modules {

FileSystemAnalyzer::FileSystemAnalyzer(QObject *parent) : QObject(parent) {}

FileSystemAnalyzer::~FileSystemAnalyzer() {
    cancel();
}

void FileSystemAnalyzer::scanDirectory(const QString &rootPath,
                                        bool recursive,
                                        bool computeHashes) {
    m_cancelled.store(false);
    m_results.clear();
    m_summary = ScanSummary{};
    m_computeHashes = computeHashes;

    LOG_INFO(QString("Starting FS scan: %1").arg(rootPath));

    QDir root(rootPath);
    if (!root.exists()) {
        emit errorOccurred("Path does not exist: " + rootPath);
        return;
    }

    if (recursive) {
        scanRecursive(rootPath);
    } else {
        QFileInfoList list = root.entryInfoList(QDir::Files | QDir::NoDotAndDotDot);
        for (const auto &fi : list) {
            if (m_cancelled.load()) break;
            FileEntry entry;
            entry.path       = fi.absoluteFilePath();
            entry.name       = fi.fileName();
            entry.size       = fi.size();
            entry.extension  = fi.suffix().toLower();
            entry.created    = fi.birthTime();
            entry.modified   = fi.lastModified();
            entry.accessed   = fi.lastRead();
            entry.isHidden   = fi.isHidden();
            entry.isSymlink  = fi.isSymLink();
            entry.mimeType   = detectMimeType(fi.absoluteFilePath());
            if (m_computeHashes) {
                auto h       = Forensic::Core::HashEngine::computeAll(fi.absoluteFilePath());
                entry.sha256 = h.sha256;
                entry.md5    = h.md5;
            }
            m_results.append(entry);
            emit fileFound(entry);
        }
    }

    m_summary.totalFiles = m_results.size();
    m_summary.hiddenFiles = static_cast<int>(std::count_if(
        m_results.begin(), m_results.end(),
        [](const FileEntry &e){ return e.isHidden; }));

    // Detect duplicates by SHA256
    QMap<QString, int> hashCount;
    for (const auto &e : m_results)
        if (!e.sha256.isEmpty()) hashCount[e.sha256]++;
    for (const auto &e : m_results)
        if (!e.sha256.isEmpty() && hashCount[e.sha256] > 1)
            m_summary.duplicates++;

    emit progressChanged(100, "Complete");
    emit scanComplete(m_summary);
    LOG_INFO(QString("FS scan complete: %1 files").arg(m_summary.totalFiles));
}

void FileSystemAnalyzer::scanRecursive(const QString &path) {
    if (m_cancelled.load()) return;

    QDir dir(path);
    QFileInfoList entries = dir.entryInfoList(
        QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);

    for (const auto &fi : entries) {
        if (m_cancelled.load()) return;

        if (fi.isDir()) {
            m_summary.totalDirs++;
            scanRecursive(fi.absoluteFilePath());
        } else {
            FileEntry entry;
            entry.path       = fi.absoluteFilePath();
            entry.name       = fi.fileName();
            entry.size       = fi.size();
            entry.extension  = fi.suffix().toLower();
            entry.created    = fi.birthTime();
            entry.modified   = fi.lastModified();
            entry.accessed   = fi.lastRead();
            entry.isHidden   = fi.isHidden();
            entry.isSymlink  = fi.isSymLink();
            entry.mimeType   = detectMimeType(fi.absoluteFilePath());

#ifdef Q_OS_WIN
            DWORD attr = GetFileAttributesW(
                reinterpret_cast<const wchar_t*>(fi.absoluteFilePath().utf16()));
            if (attr != INVALID_FILE_ATTRIBUTES) {
                entry.isSystem = (attr & FILE_ATTRIBUTE_SYSTEM) != 0;
                entry.isHidden = (attr & FILE_ATTRIBUTE_HIDDEN) != 0;
            }
#endif

            if (m_computeHashes && fi.size() < 512 * 1024 * 1024LL) { // skip >512MB
                auto h       = Forensic::Core::HashEngine::computeAll(fi.absoluteFilePath());
                entry.sha256 = h.sha256;
                entry.md5    = h.md5;
            }

            m_summary.totalSize += fi.size();
            m_results.append(entry);
            emit fileFound(entry);

            int pct = (m_summary.totalFiles > 0)
                    ? qMin(99, (m_results.size() * 99) / (m_summary.totalFiles + 1))
                    : 0;
            emit progressChanged(pct, fi.absoluteFilePath());
        }
    }
}

void FileSystemAnalyzer::cancel() {
    m_cancelled.store(true);
}

QList<FileEntry> FileSystemAnalyzer::duplicates() const {
    QMap<QString, QList<int>> byHash;
    for (int i = 0; i < m_results.size(); i++) {
        const auto &e = m_results[i];
        if (!e.sha256.isEmpty()) byHash[e.sha256].append(i);
    }
    QList<FileEntry> dups;
    for (auto &group : byHash) {
        if (group.size() > 1) {
            for (int idx : group) dups.append(m_results[idx]);
        }
    }
    return dups;
}

QList<FileEntry> FileSystemAnalyzer::hiddenFiles() const {
    QList<FileEntry> result;
    for (const auto &e : m_results) {
        if (e.isHidden || e.isSystem) result.append(e);
    }
    return result;
}

QJsonObject FileSystemAnalyzer::toJson() const {
    QJsonArray arr;
    for (const auto &e : m_results) {
        arr.append(QJsonObject{
            {"path",      e.path},
            {"name",      e.name},
            {"size",      e.size},
            {"extension", e.extension},
            {"modified",  e.modified.toString(Qt::ISODate)},
            {"sha256",    e.sha256},
            {"md5",       e.md5},
            {"isHidden",  e.isHidden},
            {"isSystem",  e.isSystem},
            {"mimeType",  e.mimeType}
        });
    }
    QJsonObject summaryObj;
    summaryObj["totalFiles"]     = m_summary.totalFiles;
    summaryObj["totalDirs"]      = m_summary.totalDirs;
    summaryObj["hiddenFiles"]    = m_summary.hiddenFiles;
    summaryObj["duplicates"]     = m_summary.duplicates;
    summaryObj["totalSizeBytes"] = m_summary.totalSize;
    QJsonObject result;
    result["summary"] = summaryObj;
    result["files"]   = arr;
    return result;
}

QString FileSystemAnalyzer::detectMimeType(const QString &path) {
    static QMimeDatabase db;
    return db.mimeTypeForFile(path).name();
}

} // namespace Forensic::Modules
