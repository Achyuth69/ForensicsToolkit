#include <QtTest/QtTest>
#include <QTemporaryFile>
#include <QTextStream>
#include "HashEngine.h"

class TestHashEngine : public QObject {
    Q_OBJECT

private slots:
    void initTestCase() {}

    void test_knownMd5() {
        // "hello\n" -> MD5: b1946ac92492d2347c6235b4d2611184
        QTemporaryFile f;
        QVERIFY(f.open());
        QTextStream ts(&f);
        ts << "hello\n";
        f.flush();

        QString md5 = Forensic::Core::HashEngine::computeMD5(f.fileName());
        QCOMPARE(md5.toLower(), QString("b1946ac92492d2347c6235b4d2611184"));
    }

    void test_knownSha256() {
        // "hello\n" -> SHA256: 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
        QTemporaryFile f;
        QVERIFY(f.open());
        QTextStream ts(&f);
        ts << "hello\n";
        f.flush();

        QString sha256 = Forensic::Core::HashEngine::computeSHA256(f.fileName());
        QCOMPARE(sha256.toLower(),
            QString("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"));
    }

    void test_computeAll() {
        QTemporaryFile f;
        QVERIFY(f.open());
        QTextStream ts(&f);
        ts << "ForensicToolkit test data";
        f.flush();

        auto hashes = Forensic::Core::HashEngine::computeAll(f.fileName());
        QVERIFY(hashes.valid);
        QVERIFY(!hashes.md5.isEmpty());
        QVERIFY(!hashes.sha1.isEmpty());
        QVERIFY(!hashes.sha256.isEmpty());
        QCOMPARE(hashes.md5.length(),    32);
        QCOMPARE(hashes.sha1.length(),   40);
        QCOMPARE(hashes.sha256.length(), 64);
    }

    void test_verify_pass() {
        QTemporaryFile f;
        QVERIFY(f.open());
        QTextStream ts(&f);
        ts << "verify me";
        f.flush();

        QString sha256 = Forensic::Core::HashEngine::computeSHA256(f.fileName());
        QVERIFY(Forensic::Core::HashEngine::verify(f.fileName(), sha256));
    }

    void test_verify_fail() {
        QTemporaryFile f;
        QVERIFY(f.open());
        QTextStream ts(&f);
        ts << "original content";
        f.flush();

        // Wrong hash should fail
        QVERIFY(!Forensic::Core::HashEngine::verify(f.fileName(),
            "0000000000000000000000000000000000000000000000000000000000000000"));
    }

    void test_bufferHash() {
        QByteArray data = "test buffer data";
        QString h1 = Forensic::Core::HashEngine::computeBufferSHA256(data);
        QString h2 = Forensic::Core::HashEngine::computeBufferSHA256(data);
        QCOMPARE(h1, h2);
        QCOMPARE(h1.length(), 64);
    }

    void test_nonexistentFile() {
        auto h = Forensic::Core::HashEngine::computeAll("/nonexistent/path/file.bin");
        QVERIFY(!h.valid);
        QVERIFY(h.md5.isEmpty());
        QVERIFY(h.sha256.isEmpty());
    }

    void test_emptyFile() {
        QTemporaryFile f;
        QVERIFY(f.open());
        f.flush();

        auto h = Forensic::Core::HashEngine::computeAll(f.fileName());
        QVERIFY(h.valid);
        // SHA256 of empty = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        QCOMPARE(h.sha256.toLower(),
            QString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }
};

QTEST_MAIN(TestHashEngine)
#include "test_hash.moc"
