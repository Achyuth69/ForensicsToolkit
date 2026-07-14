# Changelog

All notable changes to ForensicToolkit are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — Initial Release

### Added
- **Case Management** — Full CRUD for forensic cases, evidence, investigators, notes with SQLite persistence
- **File System Analyzer** — Recursive directory scan with MD5/SHA1/SHA256 hashing, hidden/system file detection, duplicate detection via hash comparison, MIME type identification
- **File Integrity Module** — Baseline snapshot creation (JSON), tamper/modification/missing file detection against baseline
- **Memory Analyzer** — Memory dump image import, string extraction, heuristic process list parsing, network connection extraction, suspicious process flagging
- **Network Forensics** — Native PCAP file parser (no libpcap dependency), TCP/UDP/DNS/HTTP/HTTPS protocol detection, top IP tracking, suspicious host flagging
- **Windows Event Log Parser** — XML export parser for EVTX logs, automatic classification of 20+ Windows Event IDs, failed login / USB insertion / process execution detection
- **Malware Detector** — YARA-compatible rule engine with text/hex pattern matching, built-in heuristic rules (10 rule categories), PE extension mismatch detection, batch directory scanning
- **AI Investigation Assistant** — Connects to OpenAI / Anthropic / Ollama / OpenRouter APIs, streaming responses, investigation summary / attack timeline / IOC / executive report generation
- **Report Generator** — PDF (via QPrinter), HTML (self-contained with embedded CSS), and JSON export with full case data
- **Dashboard** — Metric cards (evidence count, threat score, network alerts, malware hits), threat distribution pie chart, protocol distribution bar chart
- **Dark Theme** — Catppuccin Mocha color scheme via QSS stylesheet
- **Modular Architecture** — Service/repository layers, plugin interface, thread-safe design throughout
- **Unit Tests** — 6 unit test suites (HashEngine, FileSystemAnalyzer, FileIntegrityModule, MalwareDetector, CaseService, ForensicUtils)
- **Integration Tests** — Full investigation workflow end-to-end test
- **Build Scripts** — Windows (.bat) and Linux (.sh) build scripts with dependency checks
- **API Documentation** — Full API reference and architecture guide in `docs/api/`
