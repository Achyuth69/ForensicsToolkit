#include "FileIntegrityModule.h"
#include "HashEngine.h"
#include "Logger.h"
#include <QFile>
#include <QDir>
#include <QDirIterator>
#include <QJsonDocument>
#include <QJsonArray>
#include <QFileInfo>

namespace Forensic::Modules {

FileIntegrityModule::FileIntegrityModule(QObject *parent) : QObject(parent) {}

bool FileIntegrityModule::createBaseline(const QString &directory,
                                          const QString &snapshotFile) {
    QDir dir(directory);
    if (!dir.exists()) {
        emit errorOccurred("Directory not found: " + directory);
        return false;
    }

    QJsonObject snap;
    snap["directory"]  = directory;
    snap["createdAt"]  = QDateTime::currentDateTime().toString(Qt::ISODate);
    snap["version"]    = "1.0";

    QJsonArray files;
    QDirIterator it(directory, QDir::Files | QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);
    int count = 0;
    while (it.hasNext()) {
        QString fp = it.next();
        QFileInfo fi(fp);
        auto h = Forensic::Core::HashEngine::computeAll(fp);
        if (!h.valid) continue;

        files.append(QJsonObject{
            {"path",      fp},
            {"md5",       h.md5},
            {"sha1",      h.sha1},
            {"sha256",    h.sha256},
            {"size",      fi.size()},
            {"modified",  fi.lastModified().toString(Qt::ISODate)}
        });
        count++;
        emit progressChanged((count % 100) * 1, fp);
    }

    snap["files"] = files;
    LOG_INFO(QString("Baseline created: %1 files").arg(count));
    return saveSnapshot(snap, snapshotFile);
}

QList<IntegrityRecord> FileIntegrityModule::verifyAgainstBaseline(
    const QString &directory, const QString &snapshotFile)
{
    QJsonObject snap = loadSnapshot(snapshotFile);
    if (snap.isEmpty()) {
        emit errorOccurred("Cannot load snapshot: " + snapshotFile);
        return {};
    }

    QList<IntegrityRecord> results;

    // Build map from snapshot
    QMap<QString, QJsonObject> baseline;
    for (auto v : snap["files"].toArray())
        baseline[v.toObject()["path"].toString()] = v.toObject();

    // Check current files against baseline
    QDirIterator it(directory, QDir::Files | QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);
    int total = 0, modified = 0, missing = 0;

    while (it.hasNext()) {
        QString fp = it.next();
        QFileInfo fi(fp);
        auto h = Forensic::Core::HashEngine::computeAll(fp);

        IntegrityRecord rec;
        rec.path          = fp;
        rec.sha256        = h.sha256;
        rec.md5           = h.md5;
        rec.sha1          = h.sha1;
        rec.size          = fi.size();
        rec.snapshotTime  = QDateTime::currentDateTime();

        if (baseline.contains(fp)) {
            QString baseSha256 = baseline[fp]["sha256"].toString();
            rec.previousHash  = baseSha256;
            if (h.sha256 != baseSha256) {
                rec.status = IntegrityStatus::Modified;
                modified++;
            } else {
                rec.status = IntegrityStatus::Clean;
            }
            baseline.remove(fp);
        } else {
            rec.status = IntegrityStatus::New;
        }

        results.append(rec);
        total++;
        emit progressChanged((total % 100), fp);
    }

    // Files in baseline but not on disk = missing
    for (auto &key : baseline.keys()) {
        IntegrityRecord rec;
        rec.path         = key;
        rec.previousHash = baseline[key]["sha256"].toString();
        rec.status       = IntegrityStatus::Missing;
        results.append(rec);
        missing++;
    }

    emit verificationComplete(total, modified, missing);
    return results;
}

IntegrityRecord FileIntegrityModule::checkFile(const QString &filePath,
                                                const QString &expectedSHA256) {
    IntegrityRecord rec;
    rec.path         = filePath;
    rec.snapshotTime = QDateTime::currentDateTime();
    QFileInfo fi(filePath);
    if (!fi.exists()) {
        rec.status = IntegrityStatus::Missing;
        return rec;
    }

    auto h     = Forensic::Core::HashEngine::computeAll(filePath);
    rec.sha256 = h.sha256;
    rec.md5    = h.md5;
    rec.sha1   = h.sha1;
    rec.size   = fi.size();

    if (!expectedSHA256.isEmpty()) {
        rec.previousHash = expectedSHA256;
        rec.status = (h.sha256.toLower() == expectedSHA256.toLower())
            ? IntegrityStatus::Clean : IntegrityStatus::Tampered;
    } else {
        rec.status = IntegrityStatus::Clean;
    }
    return rec;
}

QString FileIntegrityModule::statusString(IntegrityStatus s) {
    switch (s) {
    case IntegrityStatus::Clean:    return "Clean";
    case IntegrityStatus::Modified: return "Modified";
    case IntegrityStatus::Renamed:  return "Renamed";
    case IntegrityStatus::Missing:  return "Missing";
    case IntegrityStatus::New:      return "New";
    case IntegrityStatus::Tampered: return "Tampered";
    }
    return "Unknown";
}

QJsonObject FileIntegrityModule::toJson(const QList<IntegrityRecord> &records) const {
    QJsonArray arr;
    for (const auto &r : records) {
        arr.append(QJsonObject{
            {"path",         r.path},
            {"md5",          r.md5},
            {"sha1",         r.sha1},
            {"sha256",       r.sha256},
            {"size",         r.size},
            {"status",       statusString(r.status)},
            {"previousHash", r.previousHash},
            {"notes",        r.notes}
        });
    }
    return QJsonObject{{"records", arr}};
}

QJsonObject FileIntegrityModule::loadSnapshot(const QString &file) {
    QFile f(file);
    if (!f.open(QIODevice::ReadOnly)) return {};
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    return doc.object();
}

bool FileIntegrityModule::saveSnapshot(const QJsonObject &snap, const QString &file) {
    QFile f(file);
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.write(QJsonDocument(snap).toJson(QJsonDocument::Indented));
    return true;
}

} // namespace Forensic::Modules
