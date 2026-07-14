#include <QtTest/QtTest>
#include <QTemporaryDir>
#include "CaseService.h"
#include "FileIntegrityModule.h"
#include "HashEngine.h"
#include "MalwareDetector.h"
#include "ForensicUtils.h"

/**
 * Integration test: Full case workflow
 * Creates a case → adds evidence → creates file baseline →
 * modifies file → verifies integrity → scans for malware → checks report JSON.
 */
class TestIntegrationCase : public QObject {
    Q_OBJECT

private:
    QTemporaryDir m_workDir;
    std::unique_ptr<Forensic::Services::CaseService> m_svc;

    QString createEvidence(const QString &name, const QByteArray &content) {
        QString path = m_workDir.path() + "/" + name;
        QFile f(path);
        if (f.open(QIODevice::WriteOnly)) f.write(content);
        return path;
    }

private slots:
    void initTestCase() {
        QVERIFY(m_workDir.isValid());
        m_svc = std::make_unique<Forensic::Services::CaseService>();
        QVERIFY(m_svc->openDatabase(m_workDir.path() + "/integration.db"));
    }

    void test_fullCaseWorkflow() {
        // 1. Create case
        auto c = m_svc->createCase(
            "Integration Test Case",
            "INT-2024-001",
            "Full workflow integration test");
        QVERIFY(!c.id.isEmpty());

        // 2. Add investigator
        Forensic::Core::Investigator inv;
        inv.name  = "Test Investigator";
        inv.email = "test@lab.gov";
        inv.badge = "T-001";
        inv.role  = "Analyst";
        QVERIFY(m_svc->addInvestigator(c.id, inv));

        // 3. Create evidence file and compute hash
        QString evPath = createEvidence("evidence.bin",
            "This is simulated forensic evidence data.");
        QString sha256 = Forensic::Core::HashEngine::computeSHA256(evPath);
        QVERIFY(!sha256.isEmpty());
        QCOMPARE(sha256.length(), 64);

        // 4. Add evidence to case
        Forensic::Core::EvidenceItem ev;
        ev.label    = "Binary Evidence";
        ev.type     = "file";
        ev.filePath = evPath;
        ev.hash     = sha256;
        ev.sizeBytes= QFileInfo(evPath).size();
        QVERIFY(m_svc->addEvidence(c.id, ev));

        // 5. Create integrity baseline
        QString snapFile = m_workDir.path() + "/baseline.json";
        Forensic::Modules::FileIntegrityModule integrity;
        QVERIFY(integrity.createBaseline(m_workDir.path(), snapFile));
        QVERIFY(QFile::exists(snapFile));

        // 6. Tamper with evidence file
        createEvidence("evidence.bin", "TAMPERED: evidence has been modified!");

        // 7. Verify integrity — should detect modification
        auto records = integrity.verifyAgainstBaseline(m_workDir.path(), snapFile);
        bool detectedTampering = false;
        for (auto &r : records) {
            if (r.path.contains("evidence.bin") &&
                (r.status == Forensic::Modules::IntegrityStatus::Modified ||
                 r.status == Forensic::Modules::IntegrityStatus::Tampered))
                detectedTampering = true;
        }
        QVERIFY(detectedTampering);

        // 8. Scan tampered file for malware
        Forensic::Modules::MalwareDetector detector;
        auto scan = detector.scanFile(evPath);
        QVERIFY(scan.scanned);
        QVERIFY(!scan.sha256.isEmpty());

        // 9. Verify evidence
        auto evList = m_svc->evidenceForCase(c.id);
        QVERIFY(!evList.isEmpty());
        QVERIFY(m_svc->verifyEvidence(c.id, evList[0].id));

        // 10. Add case note
        Forensic::Core::CaseNote note;
        note.authorId = inv.name;
        note.content  = QString("Integrity check detected tampering. "
                                "Original SHA-256: %1").arg(sha256);
        QVERIFY(m_svc->addNote(c.id, note));

        // 11. Final state check
        auto finalCase = m_svc->getCase(c.id);
        QVERIFY(finalCase.has_value());
        QCOMPARE(finalCase->investigators.size(), 1);
        QCOMPARE(finalCase->evidence.size(),      1);
        QCOMPARE(finalCase->notes.size(),         1);
        QVERIFY(finalCase->evidence[0].verified);

        // 12. JSON serialization
        QJsonObject json = finalCase->toJson();
        QVERIFY(json.contains("id"));
        QVERIFY(json.contains("investigators"));
        QVERIFY(json.contains("evidence"));
        QVERIFY(json.contains("notes"));
        QCOMPARE(json["investigators"].toArray().size(), 1);
        QCOMPARE(json["evidence"].toArray().size(),      1);
    }

    void test_formatBytes_integration() {
        qint64 bytes = 1024 * 1024 * 5; // 5 MB
        QCOMPARE(Forensic::Utils::formatBytes(bytes), QString("5.00 MB"));
    }

    void cleanupTestCase() {
        m_svc.reset();
    }
};

QTEST_MAIN(TestIntegrationCase)
#include "test_integration_case.moc"
