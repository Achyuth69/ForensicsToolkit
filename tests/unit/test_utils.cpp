#include <QtTest/QtTest>
#include "ForensicUtils.h"

class TestForensicUtils : public QObject {
    Q_OBJECT

private slots:
    void test_formatBytes() {
        QCOMPARE(Forensic::Utils::formatBytes(0),           QString("0 B"));
        QCOMPARE(Forensic::Utils::formatBytes(512),         QString("512 B"));
        QCOMPARE(Forensic::Utils::formatBytes(1024),        QString("1.0 KB"));
        QCOMPARE(Forensic::Utils::formatBytes(1536),        QString("1.5 KB"));
        QCOMPARE(Forensic::Utils::formatBytes(1048576),     QString("1.00 MB"));
        QCOMPARE(Forensic::Utils::formatBytes(1073741824),  QString("1.00 GB"));
        QCOMPARE(Forensic::Utils::formatBytes(-1),          QString("N/A"));
    }

    void test_truncate() {
        QCOMPARE(Forensic::Utils::truncate("short", 20),    QString("short"));
        QCOMPARE(Forensic::Utils::truncate("hello world!", 8), QString("hello..."));
        QCOMPARE(Forensic::Utils::truncate("", 10),         QString(""));
    }

    void test_sanitizeFilename() {
        QCOMPARE(Forensic::Utils::sanitizeFilename("valid_file.txt"),  QString("valid_file.txt"));
        QCOMPARE(Forensic::Utils::sanitizeFilename("bad/file\\name"),  QString("bad_file_name"));
        QCOMPARE(Forensic::Utils::sanitizeFilename("report:<2024>"),   QString("report__2024_"));
    }

    void test_isValidIpv4() {
        QVERIFY(Forensic::Utils::isValidIpv4("192.168.1.1"));
        QVERIFY(Forensic::Utils::isValidIpv4("0.0.0.0"));
        QVERIFY(Forensic::Utils::isValidIpv4("255.255.255.255"));
        QVERIFY(!Forensic::Utils::isValidIpv4("256.0.0.1"));
        QVERIFY(!Forensic::Utils::isValidIpv4("192.168.1"));
        QVERIFY(!Forensic::Utils::isValidIpv4("not.an.ip.address"));
        QVERIFY(!Forensic::Utils::isValidIpv4(""));
    }

    void test_threatLabel() {
        QCOMPARE(Forensic::Utils::threatLabel(0),   QString("None"));
        QCOMPARE(Forensic::Utils::threatLabel(10),  QString("Low"));
        QCOMPARE(Forensic::Utils::threatLabel(40),  QString("Medium"));
        QCOMPARE(Forensic::Utils::threatLabel(60),  QString("High"));
        QCOMPARE(Forensic::Utils::threatLabel(90),  QString("Critical"));
        QCOMPARE(Forensic::Utils::threatLabel(100), QString("Critical"));
    }

    void test_hexDump_basicOutput() {
        QByteArray data = "ABCDEFGH";
        QString dump = Forensic::Utils::hexDump(data, 256);
        QVERIFY(dump.contains("41"));   // 'A' in hex
        QVERIFY(dump.contains("ABCDEFGH"));
    }

    void test_hexDump_truncated() {
        QByteArray data(512, 'X');
        QString dump = Forensic::Utils::hexDump(data, 16);
        QVERIFY(dump.contains("more bytes"));
    }

    void test_formatTimestamp_valid() {
        QDateTime dt(QDate(2024, 6, 15), QTime(14, 30, 0));
        QString s = Forensic::Utils::formatTimestamp(dt);
        QVERIFY(s.contains("2024"));
        QVERIFY(s.contains("14:30"));
    }

    void test_formatTimestamp_invalid() {
        QString s = Forensic::Utils::formatTimestamp(QDateTime());
        QCOMPARE(s, QString("Unknown"));
    }
};

QTEST_MAIN(TestForensicUtils)
#include "test_utils.moc"
