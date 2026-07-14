# ForensicToolkit — API Reference

## Namespace: `Forensic::Core`

### `ForensicCase`
Central data model for a forensic investigation.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `QString` | UUID, auto-generated |
| `title` | `QString` | Human-readable case name |
| `caseNumber` | `QString` | Official case reference (e.g. `FT-2024-001`) |
| `status` | `CaseStatus` | `Open` \| `InProgress` \| `Closed` \| `Archived` |
| `investigators` | `QList<Investigator>` | Assigned team members |
| `evidence` | `QList<EvidenceItem>` | Acquired evidence items |
| `notes` | `QList<CaseNote>` | Investigator notes |

```cpp
// Serialize to JSON
QJsonObject json = myCase.toJson();

// Deserialize from JSON
ForensicCase c = ForensicCase::fromJson(jsonObject);
```

---

### `HashEngine`
Thread-safe cryptographic hash computation using OpenSSL EVP.

```cpp
// Compute all three hashes in a single file pass (most efficient)
FileHashes h = HashEngine::computeAll("/path/to/file");
qDebug() << h.md5 << h.sha1 << h.sha256;

// Individual hash
QString sha256 = HashEngine::computeSHA256("/path/to/file");

// Verify against a known hash
bool ok = HashEngine::verify("/path/to/file", expectedSHA256);

// Hash a buffer
QString hash = HashEngine::computeBufferSHA256(byteArray);
```

---

### `Logger`
Singleton thread-safe structured logger.

```cpp
// Using macros (recommended)
LOG_INFO("Starting analysis");
LOG_WARN("File skipped: permission denied");
LOG_ERROR("Failed to open database");

// Direct API
Logger::instance().setLogFile("/logs/forensic.log");
Logger::instance().setMinLevel(LogLevel::Debug);

// Add a custom sink (e.g., to send logs to a UI widget)
Logger::instance().addSink([](const LogEntry &e) {
    ui->appendLog(e.message);
});
```

---

### `ThreadPool`
Application-wide thread pool wrapping `QThreadPool`.

```cpp
// Submit a background task
ThreadPool::instance().submit(
    []() { /* heavy work */ },
    []() { /* called on completion */ }
);

// Wait for all tasks to complete
ThreadPool::instance().waitForAll();
```

---

## Namespace: `Forensic::Modules`

### `FileSystemAnalyzer`
```cpp
FileSystemAnalyzer analyzer;

// Connect signals before scanning
connect(&analyzer, &FileSystemAnalyzer::fileFound,
    [](const FileEntry &e) { qDebug() << e.path; });
connect(&analyzer, &FileSystemAnalyzer::scanComplete,
    [](const ScanSummary &s) { qDebug() << s.totalFiles; });

// Start recursive scan with hash computation
analyzer.scanDirectory("/target/path", /*recursive=*/true, /*hashes=*/true);

// Get results
QList<FileEntry> all  = analyzer.results();
QList<FileEntry> dups = analyzer.duplicates();
QList<FileEntry> hidden = analyzer.hiddenFiles();

// Export as JSON
QJsonObject json = analyzer.toJson();

// Cancel a running scan
analyzer.cancel();
```

---

### `FileIntegrityModule`
```cpp
FileIntegrityModule mod;

// 1. Create a baseline snapshot
mod.createBaseline("/monitored/dir", "/snapshots/baseline.json");

// 2. Later, verify against the baseline
QList<IntegrityRecord> results =
    mod.verifyAgainstBaseline("/monitored/dir", "/snapshots/baseline.json");

for (auto &r : results) {
    if (r.status == IntegrityStatus::Modified)
        qWarning() << "TAMPERED:" << r.path;
    if (r.status == IntegrityStatus::Missing)
        qWarning() << "MISSING:"  << r.path;
}

// 3. Check a single file with a known hash
IntegrityRecord rec = mod.checkFile("/path/to/file.bin", expectedSHA256);
```

---

### `MemoryAnalyzer`
```cpp
MemoryAnalyzer mem;

connect(&mem, &MemoryAnalyzer::progressChanged,
    [](int pct, const QString &stage) { qDebug() << pct << stage; });
connect(&mem, &MemoryAnalyzer::analysisComplete,
    [](const MemoryAnalysisResult &r) {
        qDebug() << r.processes.size() << "processes";
        qDebug() << r.strings.size()   << "strings";
    });

mem.analyzeImage("/evidence/memory.raw");
```

---

### `NetworkForensics`
```cpp
NetworkForensics net;

connect(&net, &NetworkForensics::analysisComplete,
    [](const NetworkSummary &s) {
        qDebug() << s.totalPackets << "packets";
        qDebug() << s.suspiciousPackets << "suspicious";
    });

net.loadPcap("/evidence/capture.pcap");

// Filter after analysis
QList<Packet> httpPkts = net.filterByProtocol(Protocol::HTTP);
QList<Packet> fromIp   = net.filterByIp("192.168.1.100");
```

---

### `EventLogParser`
```cpp
EventLogParser parser;

connect(&parser, &EventLogParser::parseComplete,
    [](const EventLogSummary &s) {
        qDebug() << s.failedLogins << "failed logins";
        qDebug() << s.flaggedEvents << "flagged events";
    });

// Parse Windows Event Viewer XML export
parser.parseXmlExport("/evidence/security.xml");

// Filter results
auto failedLogins = parser.filterByCategory(EventCategory::FailedLogin);
auto usbEvents    = parser.filterByCategory(EventCategory::UsbInsertion);
```

---

### `MalwareDetector`
```cpp
MalwareDetector detector;

// Load YARA rules
detector.loadRules("/rules/");            // directory
detector.loadRuleFile("/rules/apt.yar");  // single file

// Scan single file
MalwareScanResult result = detector.scanFile("/samples/suspicious.exe");
qDebug() << result.verdict;
qDebug() << MalwareDetector::threatString(result.maxThreat);
for (auto &m : result.matches)
    qDebug() << m.ruleName << m.description;

// Batch scan
connect(&detector, &MalwareDetector::threatDetected,
    [](const MalwareScanResult &r) {
        qWarning() << "THREAT:" << r.filePath << r.verdict;
    });
detector.scanDirectory("/target/", /*recursive=*/true);
```

---

### `AiAssistant`
```cpp
AiAssistant ai;

// Configure
AiConfig cfg;
cfg.provider = "openai";          // or "anthropic", "ollama", "openrouter"
cfg.apiKey   = "sk-...";
cfg.model    = "gpt-4o";
cfg.maxTokens = 4096;
ai.setConfig(cfg);

// Analyze evidence context
connect(&ai, &AiAssistant::responseReady,
    [](const InvestigationReport &r) {
        qDebug() << r.summary;
        qDebug() << r.attackTimeline;
        qDebug() << r.recommendedActions;
    });

QJsonObject evidenceContext;
evidenceContext["caseTitle"] = "Ransomware Incident";
evidenceContext["malwareFindings"] = malwareJson;
evidenceContext["networkSummary"]  = networkJson;

ai.analyzeEvidence(evidenceContext);

// Ask specific questions
ai.askQuestion("What attack vector was most likely used?", evidenceContext);

// Generate full executive report
ai.generateExecutiveReport(fullCaseJson);
```

---

### `ReportGenerator`
```cpp
ReportGenerator gen;

ReportConfig cfg;
cfg.format              = ReportFormat::PDF;        // PDF | HTML | JSON
cfg.outputPath          = "/reports/case001.pdf";
cfg.companyName         = "Digital Forensics Lab";
cfg.classificationLabel = "CONFIDENTIAL";
cfg.includeTimeline     = true;
cfg.includeEvidence     = true;
cfg.includeNetwork      = true;
cfg.includeMalware      = true;
cfg.includeAiSummary    = true;

connect(&gen, &ReportGenerator::reportGenerated,
    [](const QString &path) { qDebug() << "Report saved:" << path; });

gen.generate(cfg, myCase, analysisData);
```

---

## Namespace: `Forensic::Services`

### `CaseService`
The primary business-logic entry point. All UI code talks to this.

```cpp
CaseService svc;
svc.openDatabase("/data/forensic.db");

// CRUD
ForensicCase c = svc.createCase("Breach Investigation", "FT-001", "Description");
svc.updateCase(c);
auto opt = svc.getCase(c.id);       // returns std::optional<ForensicCase>
QList<ForensicCase> all = svc.allCases();
svc.deleteCase(c.id);

// Evidence
EvidenceItem ev;
ev.label    = "Hard Drive Image";
ev.type     = "disk_image";
ev.filePath = "/evidence/disk.img";
ev.hash     = sha256;
svc.addEvidence(c.id, ev);
svc.verifyEvidence(c.id, ev.id);

// Investigators
Investigator inv{"", "Alice", "alice@lab.gov", "B-001", "Lead"};
svc.addInvestigator(c.id, inv);

// Notes
CaseNote note{"", c.id, "alice", "Initial triage complete."};
svc.addNote(c.id, note);
```

---

## Namespace: `Forensic::Utils`

```cpp
// Human-readable byte sizes
ForensicUtils::formatBytes(1048576);   // "1.00 MB"
ForensicUtils::formatBytes(1536);      // "1.5 KB"

// Timestamp formatting
ForensicUtils::formatTimestamp(QDateTime::currentDateTime());
// → "2024-06-15  14:30:00  (Sat)"

// String utilities
ForensicUtils::truncate("very long string here", 12);  // "very long..."
ForensicUtils::sanitizeFilename("report:<2024>");       // "report__2024_"

// Validation
ForensicUtils::isValidIpv4("192.168.1.1");  // true
ForensicUtils::isValidIpv4("999.0.0.1");    // false

// Risk assessment
ForensicUtils::threatLabel(85);  // "Critical"
ForensicUtils::threatLabel(40);  // "Medium"

// Hex dump
QString dump = ForensicUtils::hexDump(byteArray, 64);
```

---

## Plugin System: `Forensic::Core::IAnalyzerPlugin`

Implement this interface to add custom analyzers:

```cpp
class MyCustomAnalyzer : public Forensic::Core::IAnalyzerPlugin {
public:
    PluginMeta meta() const override {
        return {"my.analyzer", "Custom Analyzer", "1.0",
                "Author", "Description", PluginType::Analyzer};
    }
    bool initialize(const QVariantMap &config) override { /* ... */ return true; }
    void shutdown() override {}

    QJsonObject analyze(const QString &targetPath,
                        const QVariantMap &options) override {
        // Your analysis logic
        return QJsonObject{{"result", "..."}};
    }
    int progressPercent() const override { return m_progress; }
    bool supportsTarget(const QString &path) const override {
        return path.endsWith(".custom");
    }
private:
    int m_progress{0};
};
```
