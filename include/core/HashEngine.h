#pragma once
#include <QString>
#include <QByteArray>
#include <QtGlobal>
#include <openssl/evp.h>

namespace Forensic::Core {

struct FileHashes {
    QString md5;
    QString sha1;
    QString sha256;
    bool    valid{false};
};

class HashEngine {
public:
    /// Compute MD5 + SHA1 + SHA256 in one file pass (most efficient)
    static FileHashes computeAll(const QString &filePath);

    static QString computeMD5   (const QString &filePath);
    static QString computeSHA1  (const QString &filePath);
    static QString computeSHA256(const QString &filePath);

    static QString computeBufferMD5   (const QByteArray &data);
    static QString computeBufferSHA256(const QByteArray &data);

    /// Returns true if the file's SHA-256 matches expectedSHA256 (case-insensitive)
    static bool verify(const QString &filePath, const QString &expectedSHA256);

private:
    static QString hexDigest      (const QString    &path, const EVP_MD *md);
    static QString hexDigestBuffer(const QByteArray &data, const EVP_MD *md);

    static constexpr qint64 BUFFER_SIZE = 1LL << 20; // 1 MB read buffer
};

} // namespace Forensic::Core
