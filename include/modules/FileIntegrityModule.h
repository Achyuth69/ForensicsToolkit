#pragma once
#include <QObject>
#include <QString>
#include <QList>
#include <QJsonObject>
#include <QDateTime>

namespace Forensic::Modules {

enum class IntegrityStatus { Clean, Modified, Renamed, Missing, New, Tampered };

struct IntegrityRecord {
    QString         path;
    QString         md5;
    QString         sha1;
    QString         sha256;
    qint64          size{0};
    QDateTime       snapshotTime;
    IntegrityStatus status{IntegrityStatus::Clean};
    QString         previousHash;
    QString         notes;
};

class FileIntegrityModule : public QObject {
    Q_OBJECT
public:
    explicit FileIntegrityModule(QObject *parent = nullptr);

    // Create baseline snapshot
    bool createBaseline(const QString &directory, const QString &snapshotFile);

    // Verify against existing baseline
    QList<IntegrityRecord> verifyAgainstBaseline(const QString &directory,
                                                  const QString &snapshotFile);

    // Single file check
    IntegrityRecord checkFile(const QString &filePath,
                               const QString &expectedSHA256 = {});

    static QString statusString(IntegrityStatus s);
    QJsonObject    toJson(const QList<IntegrityRecord> &records) const;

signals:
    void progressChanged(int percent, const QString &file);
    void verificationComplete(int total, int modified, int missing);
    void errorOccurred(const QString &error);

private:
    QJsonObject loadSnapshot(const QString &snapshotFile);
    bool        saveSnapshot(const QJsonObject &snap, const QString &file);
};

} // namespace Forensic::Modules
