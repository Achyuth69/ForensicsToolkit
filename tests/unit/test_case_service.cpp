#include <QtTest/QtTest>
#include <QTemporaryDir>
#include "CaseService.h"
#include "ForensicCase.h"

class TestCaseService : public QObject {
    Q_OBJECT

private:
    QTemporaryDir m_dir;
    std::unique_ptr<Forensic::Services::CaseService> m_svc;

private slots:
    void initTestCase() {
        QVERIFY(m_dir.isValid());
        m_svc = std::make_unique<Forensic::Services::CaseService>();
        QVERIFY(m_svc->openDatabase(m_dir.path() + "/test.db"));
    }

    void test_createCase() {
        auto c = m_svc->createCase("Test Case Alpha", "FT-001", "A test case");
        QVERIFY(!c.id.isEmpty());
        QCOMPARE(c.title,      QString("Test Case Alpha"));
        QCOMPARE(c.caseNumber, QString("FT-001"));
        QCOMPARE(c.status,     Forensic::Core::CaseStatus::Open);
    }

    void test_getCase() {
        auto c = m_svc->createCase("Retrieve Test", "FT-002", "desc");
        auto fetched = m_svc->getCase(c.id);
        QVERIFY(fetched.has_value());
        QCOMPARE(fetched->title, QString("Retrieve Test"));
    }

    void test_allCases() {
        int before = m_svc->allCases().size();
        m_svc->createCase("Case A", "FT-003", "");
        m_svc->createCase("Case B", "FT-004", "");
        QCOMPARE(m_svc->allCases().size(), before + 2);
    }

    void test_updateCase() {
        auto c = m_svc->createCase("Original Title", "FT-005", "");
        c.title = "Updated Title";
        QVERIFY(m_svc->updateCase(c));
        auto updated = m_svc->getCase(c.id);
        QVERIFY(updated.has_value());
        QCOMPARE(updated->title, QString("Updated Title"));
    }

    void test_deleteCase() {
        auto c = m_svc->createCase("To Delete", "FT-006", "");
        QVERIFY(m_svc->getCase(c.id).has_value());
        QVERIFY(m_svc->deleteCase(c.id));
        QVERIFY(!m_svc->getCase(c.id).has_value());
    }

    void test_addEvidence() {
        auto c = m_svc->createCase("Evidence Case", "FT-007", "");

        Forensic::Core::EvidenceItem ev;
        ev.label    = "Hard Drive Image";
        ev.type     = "disk_image";
        ev.filePath = "/evidence/disk.img";
        ev.hash     = QString(64, 'a'); // fake SHA256

        QVERIFY(m_svc->addEvidence(c.id, ev));
        auto evList = m_svc->evidenceForCase(c.id);
        QCOMPARE(evList.size(), 1);
        QCOMPARE(evList[0].label, QString("Hard Drive Image"));
    }

    void test_verifyEvidence() {
        auto c = m_svc->createCase("Verify Case", "FT-008", "");
        Forensic::Core::EvidenceItem ev;
        ev.label = "Memory Dump";
        ev.type  = "memory_dump";
        m_svc->addEvidence(c.id, ev);

        auto evList = m_svc->evidenceForCase(c.id);
        QVERIFY(!evList.isEmpty());
        QVERIFY(!evList[0].verified);

        QVERIFY(m_svc->verifyEvidence(c.id, evList[0].id));
        auto updated = m_svc->evidenceForCase(c.id);
        QVERIFY(updated[0].verified);
    }

    void test_addInvestigator() {
        auto c = m_svc->createCase("Investigator Case", "FT-009", "");

        Forensic::Core::Investigator inv;
        inv.name  = "Alice Smith";
        inv.email = "alice@lab.gov";
        inv.badge = "B-1001";
        inv.role  = "Lead";

        QVERIFY(m_svc->addInvestigator(c.id, inv));
        auto fetched = m_svc->getCase(c.id);
        QVERIFY(fetched.has_value());
        QCOMPARE(fetched->investigators.size(), 1);
        QCOMPARE(fetched->investigators[0].name, QString("Alice Smith"));
    }

    void test_addNote() {
        auto c = m_svc->createCase("Notes Case", "FT-010", "");
        Forensic::Core::CaseNote note;
        note.authorId = "alice";
        note.content  = "Initial triage complete.";
        QVERIFY(m_svc->addNote(c.id, note));

        auto fetched = m_svc->getCase(c.id);
        QVERIFY(fetched.has_value());
        QCOMPARE(fetched->notes.size(), 1);
        QCOMPARE(fetched->notes[0].content, QString("Initial triage complete."));
    }

    void test_caseJsonRoundtrip() {
        auto c = m_svc->createCase("JSON Case", "FT-011", "Testing serialization");
        QJsonObject json = c.toJson();
        QCOMPARE(json["title"].toString(), QString("JSON Case"));
        QCOMPARE(json["caseNumber"].toString(), QString("FT-011"));
        QVERIFY(!json["id"].toString().isEmpty());

        auto restored = Forensic::Core::ForensicCase::fromJson(json);
        QCOMPARE(restored.id,         c.id);
        QCOMPARE(restored.title,      c.title);
        QCOMPARE(restored.caseNumber, c.caseNumber);
    }

    void cleanupTestCase() {
        m_svc.reset();
    }
};

QTEST_MAIN(TestCaseService)
#include "test_case_service.moc"
