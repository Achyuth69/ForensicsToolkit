#include <QtTest/QtTest>
#include <QTemporaryDir>
#include <QFile>
#include <QTextStream>
#include "FileIntegrityModule.h"

class TestFileIntegrity : public QObject {
    Q_OBJECT

private:
    QTemporaryDir m_dir;

    QString createFile(const QString &name, const QString &content) {
        QString path = m_dir.path() + "/" + name;
        QFile f(path);
        if (f.open(QIODevice::WriteOnly))
            QTextStream(&f) << content;
        return path;
    }

private slots:
    void initTestCase() {
        QVERIFY(m_dir.isValid());
    }

    void test_createAndVerifyBaseline_clean() {
        createFile("a.txt", "content A");
        createFile("b.txt", "content B");

        QString snapFile = m_dir.path() + "/baseline.json";
        Forensic::Modules::FileIntegrityModule mod;
        QVERIFY(mod.createBaseline(m_dir.path(), snapFile));
        QVERIFY(QFile::exists(snapFile));

        // Verify immediately — everything should be clean
        auto results = mod.verifyAgainstBaseline(m_dir.path(), snapFile);
        int modified = 0;
        for (auto &r : results)
            if (r.status == Forensic::Modules::IntegrityStatus::Modified) modified++;
        QCOMPARE(modified, 0);
    }

    void test_detectModifiedFile() {
        createFile("secret.txt", "original");
        QString snap = m_dir.path() + "/snap2.json";

        Forensic::Modules::FileIntegrityModule mod;
        QVERIFY(mod.createBaseline(m_dir.path(), snap));

        // Modify the file
        createFile("secret.txt", "tampered content!!!");

        auto results = mod.verifyAgainstBaseline(m_dir.path(), snap);
        bool foundModified = false;
        for (auto &r : results) {
            if (r.path.contains("secret.txt") &&
                r.status == Forensic::Modules::IntegrityStatus::Modified)
                foundModified = true;
        }
        QVERIFY(foundModified);
    }

    void test_detectMissingFile() {
        createFile("willdelete.txt", "ephemeral");
        QString snap = m_dir.path() + "/snap3.json";

        Forensic::Modules::FileIntegrityModule mod;
        QVERIFY(mod.createBaseline(m_dir.path(), snap));

        // Delete the file
        QFile::remove(m_dir.path() + "/willdelete.txt");

        auto results = mod.verifyAgainstBaseline(m_dir.path(), snap);
        bool foundMissing = false;
        for (auto &r : results) {
            if (r.path.contains("willdelete.txt") &&
                r.status == Forensic::Modules::IntegrityStatus::Missing)
                foundMissing = true;
        }
        QVERIFY(foundMissing);
    }

    void test_checkSingleFile_clean() {
        QString p = createFile("single.txt", "known content");
        Forensic::Modules::FileIntegrityModule mod;

        // First compute expected hash
        Forensic::Core::HashEngine engine;
        QString expected = Forensic::Core::HashEngine::computeSHA256(p);

        auto rec = mod.checkFile(p, expected);
        QCOMPARE(rec.status, Forensic::Modules::IntegrityStatus::Clean);
    }

    void test_checkSingleFile_tampered() {
        QString p = createFile("tampered.txt", "real content");
        Forensic::Modules::FileIntegrityModule mod;

        auto rec = mod.checkFile(p,
            "0000000000000000000000000000000000000000000000000000000000000000");
        QCOMPARE(rec.status, Forensic::Modules::IntegrityStatus::Tampered);
    }

    void test_statusString() {
        using S = Forensic::Modules::IntegrityStatus;
        QCOMPARE(Forensic::Modules::FileIntegrityModule::statusString(S::Clean),    QString("Clean"));
        QCOMPARE(Forensic::Modules::FileIntegrityModule::statusString(S::Modified), QString("Modified"));
        QCOMPARE(Forensic::Modules::FileIntegrityModule::statusString(S::Missing),  QString("Missing"));
        QCOMPARE(Forensic::Modules::FileIntegrityModule::statusString(S::Tampered), QString("Tampered"));
    }
};

QTEST_MAIN(TestFileIntegrity)
#include "test_integrity.moc"
