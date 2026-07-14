#include <QtTest/QtTest>
#include <QTemporaryDir>
#include <QFile>
#include <QTextStream>
#include "FileSystemAnalyzer.h"

class TestFileSystemAnalyzer : public QObject {
    Q_OBJECT

private:
    QTemporaryDir m_dir;

    void createFile(const QString &name, const QString &content = "test") {
        QFile f(m_dir.path() + "/" + name);
        QVERIFY(f.open(QIODevice::WriteOnly));
        QTextStream ts(&f);
        ts << content;
    }

private slots:
    void initTestCase() {
        QVERIFY(m_dir.isValid());
        createFile("file1.txt",  "hello world");
        createFile("file2.txt",  "hello world");   // duplicate
        createFile("malware.exe","hello world");   // duplicate
        createFile("report.pdf", "pdf data here");
    }

    void test_scanFinds_allFiles() {
        Forensic::Modules::FileSystemAnalyzer analyzer;
        QSignalSpy spy(&analyzer,
            &Forensic::Modules::FileSystemAnalyzer::scanComplete);

        analyzer.scanDirectory(m_dir.path(), false, true);

        QCOMPARE(spy.count(), 1);
        QVERIFY(analyzer.results().size() >= 4);
    }

    void test_summaryTotalFiles() {
        Forensic::Modules::FileSystemAnalyzer analyzer;
        analyzer.scanDirectory(m_dir.path(), false, true);

        QVERIFY(analyzer.summary().totalFiles >= 4);
    }

    void test_duplicateDetection() {
        Forensic::Modules::FileSystemAnalyzer analyzer;
        analyzer.scanDirectory(m_dir.path(), false, true);

        auto dups = analyzer.duplicates();
        // file1.txt, file2.txt and malware.exe all have same content "hello world"
        QVERIFY(dups.size() >= 2);
    }

    void test_toJson() {
        Forensic::Modules::FileSystemAnalyzer analyzer;
        analyzer.scanDirectory(m_dir.path(), false, false);

        QJsonObject json = analyzer.toJson();
        QVERIFY(json.contains("summary"));
        QVERIFY(json.contains("files"));
        QVERIFY(json["files"].toArray().size() >= 4);
    }

    void test_cancelScan() {
        Forensic::Modules::FileSystemAnalyzer analyzer;
        // Cancel immediately — should not crash
        analyzer.cancel();
        analyzer.scanDirectory(m_dir.path(), false, false);
        // After cancel the scan returns quickly
        QVERIFY(true);
    }

    void test_nonExistentPath() {
        Forensic::Modules::FileSystemAnalyzer analyzer;
        QSignalSpy errSpy(&analyzer,
            &Forensic::Modules::FileSystemAnalyzer::errorOccurred);
        analyzer.scanDirectory("/this/path/does/not/exist", false, false);
        QCOMPARE(errSpy.count(), 1);
    }
};

QTEST_MAIN(TestFileSystemAnalyzer)
#include "test_filesystem.moc"
