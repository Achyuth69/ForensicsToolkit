#include "HashEngine.h"
#include <QFile>
#include <QDebug>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

namespace Forensic::Core {

FileHashes HashEngine::computeAll(const QString &filePath) {
    FileHashes hashes;
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) return hashes;

    // Initialize three EVP contexts simultaneously
    EVP_MD_CTX *md5ctx  = EVP_MD_CTX_new();
    EVP_MD_CTX *sha1ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sha256ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(md5ctx,    EVP_md5(),    nullptr);
    EVP_DigestInit_ex(sha1ctx,   EVP_sha1(),   nullptr);
    EVP_DigestInit_ex(sha256ctx, EVP_sha256(), nullptr);

    QByteArray buf(BUFFER_SIZE, Qt::Uninitialized);
    qint64 bytesRead;

    while ((bytesRead = file.read(buf.data(), BUFFER_SIZE)) > 0) {
        auto *raw = reinterpret_cast<const unsigned char*>(buf.constData());
        EVP_DigestUpdate(md5ctx,    raw, static_cast<size_t>(bytesRead));
        EVP_DigestUpdate(sha1ctx,   raw, static_cast<size_t>(bytesRead));
        EVP_DigestUpdate(sha256ctx, raw, static_cast<size_t>(bytesRead));
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  len = 0;

    EVP_DigestFinal_ex(md5ctx,    digest, &len);
    hashes.md5 = QByteArray(reinterpret_cast<char*>(digest), len).toHex();

    EVP_DigestFinal_ex(sha1ctx,   digest, &len);
    hashes.sha1 = QByteArray(reinterpret_cast<char*>(digest), len).toHex();

    EVP_DigestFinal_ex(sha256ctx, digest, &len);
    hashes.sha256 = QByteArray(reinterpret_cast<char*>(digest), len).toHex();

    EVP_MD_CTX_free(md5ctx);
    EVP_MD_CTX_free(sha1ctx);
    EVP_MD_CTX_free(sha256ctx);

    hashes.valid = true;
    return hashes;
}

QString HashEngine::computeMD5(const QString &filePath) {
    return hexDigest(filePath, EVP_md5());
}

QString HashEngine::computeSHA1(const QString &filePath) {
    return hexDigest(filePath, EVP_sha1());
}

QString HashEngine::computeSHA256(const QString &filePath) {
    return hexDigest(filePath, EVP_sha256());
}

QString HashEngine::computeBufferMD5(const QByteArray &data) {
    return hexDigestBuffer(data, EVP_md5());
}

QString HashEngine::computeBufferSHA256(const QByteArray &data) {
    return hexDigestBuffer(data, EVP_sha256());
}

bool HashEngine::verify(const QString &filePath, const QString &expectedSHA256) {
    return computeSHA256(filePath).toLower() == expectedSHA256.toLower();
}

QString HashEngine::hexDigest(const QString &path, const EVP_MD *md) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, nullptr);

    QByteArray buf(BUFFER_SIZE, Qt::Uninitialized);
    qint64 n;
    while ((n = file.read(buf.data(), BUFFER_SIZE)) > 0) {
        EVP_DigestUpdate(ctx, reinterpret_cast<const unsigned char*>(buf.constData()),
                         static_cast<size_t>(n));
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);

    return QByteArray(reinterpret_cast<char*>(digest), len).toHex();
}

QString HashEngine::hexDigestBuffer(const QByteArray &data, const EVP_MD *md) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx,
                     reinterpret_cast<const unsigned char*>(data.constData()),
                     static_cast<size_t>(data.size()));

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);

    return QByteArray(reinterpret_cast<char*>(digest), len).toHex();
}

} // namespace Forensic::Core
