# ForensicToolkit — Product Roadmap

Complete version history and future roadmap from v1.0 to vN.

---

## ✅ v1.0.0 — Foundation Release (Shipped July 2025)

The initial public release. Built from scratch on Windows with Qt6 + MSVC.

### What shipped
- **Case Manager** — SQLite-backed case database with investigator tracking and evidence chain-of-custody
- **File System Analyzer** — Recursive directory scanning, MIME detection, hidden file discovery, duplicate detection by SHA-256
- **File Integrity Monitor** — Cryptographic baseline creation and tamper detection (MD5, SHA-1, SHA-256)
- **Memory Analyzer** — Raw memory dump analysis, process extraction, string extraction, network connection parsing
- **Network Forensics** — Native PCAP parser with Ethernet/IPv4/TCP/UDP/DNS/HTTP dissection, suspicious host flagging
- **Event Log Parser** — Windows EVTX XML export parsing, failed login detection, USB event flagging, process execution tracking
- **Malware Detector** — YARA rule engine with built-in heuristics for shellcode, packed PEs, extension mismatches
- **AI Assistant** — OpenAI, Anthropic, OpenRouter, and Ollama integration for AI-powered investigation reports
- **Report Generator** — PDF, HTML, and JSON report export with full case metadata and branding
- **Dark UI** — Qt6 Catppuccin-inspired dark theme with dashboard, log view, and settings
- **Plugin System** — IAnalyzerPlugin interface scaffolded for third-party extensions
- **Installer** — Inno Setup `.exe` installer for Windows 10/11 64-bit
- **Product Website** — GitHub Pages landing page with direct download link

### Tech stack
- C++17, Qt 6.11.1, MSVC 2022, OpenSSL 4.x, SQLite (via Qt SQL)
- CMake 4.4 build system with AUTOMOC, NMake Makefiles

---

## 🔄 v1.1.0 — Stability & Polish (Planned Q3 2025)

Bug fixes and quality of life improvements based on v1.0 feedback.

- Fix EVTX binary parsing (currently requires XML export workaround)
- Add progress cancellation to all long-running scans
- Settings persistence across sessions (save API keys, theme, paths)
- Case database encryption with user password
- Export case to ZIP archive for sharing between investigators
- Import case from ZIP archive
- Auto-update checker — notify when new GitHub release is available
- Dark/Light theme toggle in Settings
- Keyboard shortcuts for all major actions
- Fix all C4996 deprecated Qt API warnings
- Improve error messages throughout the UI

---

## 🔄 v1.2.0 — Reporting & Intelligence (Planned Q4 2025)

Deeper reporting and threat intelligence integration.

- MITRE ATT&CK framework mapping in reports — auto-tag findings to ATT&CK techniques
- IOC export — export Indicators of Compromise as STIX/TAXII, plain text, or CSV
- VirusTotal API integration — check file hashes against VT database
- Threat intelligence feed support — import IOC lists from MISP or OpenCTI
- Report templates — customizable HTML/PDF templates per organization
- Digital signature verification — verify PE file signatures and certificates
- Watermarking on PDF reports — classification banner and investigator name

---

## 🚀 v2.0.0 — Advanced Analysis (Planned 2026)

Major feature release. Core forensics capabilities that professionals expect.

### Timeline Reconstruction (flagship feature)
- Unified investigation timeline combining all data sources
- File system timestamps + event log events + network sessions + memory artifacts
- Interactive visual timeline with zoom, filter by source, flag events
- Export timeline as PDF or JSON
- This is the single most requested feature in professional forensics tools

### Disk Image Support
- Mount and analyze `.dd`, `.raw`, `.E01` (EnCase), `.AFF`, `.vmdk` disk images
- Browse image contents like a file system without extracting
- Recover deleted files from unallocated space
- MFT (Master File Table) parser for NTFS volumes
- LNK file and prefetch file analysis

### Windows Registry Analyzer
- Parse registry hives directly: `NTUSER.DAT`, `SAM`, `SYSTEM`, `SOFTWARE`
- Recently opened files (MRU lists)
- USB device history with timestamps
- Installed programs and uninstall keys
- Run/RunOnce persistence keys
- User account information from SAM
- Network shares and mapped drives

### Live System Acquisition
- Capture live RAM from a running Windows machine
- Acquire disk image from a running system
- Live process list, open network connections, loaded drivers
- Works on local or remote machines (with admin credentials)

### Network Geo-IP Mapping
- Interactive world map showing IP address origins from PCAP analysis
- Uses MaxMind GeoLite2 database (offline, no API key needed)
- Color-coded by threat level
- Click country to filter packets
- Export map as image

---

## 🚀 v2.1.0 — Browser & Email Forensics (Planned 2026)

Artifact recovery from user applications.

- **Browser Forensics** — Chrome, Firefox, Edge history, cookies, cached files, downloads, saved passwords (hashed)
- **Email Forensics** — Parse `.pst`, `.ost`, `.mbox` email archives, extract attachments, recover deleted emails
- **Thumbnail Cache Analyzer** — Windows thumbs.db and thumbcache recovery
- **Recycle Bin Analyzer** — Recover deleted file metadata from `$Recycle.Bin`
- **Shellbag Analyzer** — Track folder access history from registry shellbags
- **Jump List Analyzer** — Recent files and applications from Windows Jump Lists
- **Prefetch Analyzer** — Application execution history from Windows prefetch files

---

## 🚀 v3.0.0 — Enterprise & Collaboration (Planned 2027)

Multi-investigator, networked deployment for enterprise SOC teams.

### Multi-Investigator Collaboration
- Central case server — team members connect to shared case database
- Real-time case updates across investigators
- Role-based access control (Lead Investigator, Analyst, Read-only)
- Case audit trail — every action logged with investigator name and timestamp
- Comment and annotation system on evidence items and findings

### Remote Acquisition Agent
- Lightweight agent deployed on suspect machines
- Remote RAM and disk acquisition over encrypted channel
- Live triage — collect artifacts without full acquisition
- Works across LAN or VPN

### Custom Scripting Engine
- Python scripting API for custom analysis modules
- Script editor built into the UI
- Access all parsed data (processes, packets, files, events) from scripts
- Schedule automated scans and reports

### REST API
- Full REST API for all ForensicToolkit features
- Integrate with SIEMs (Splunk, Elastic, QRadar)
- Webhook support for automated alerting
- OpenAPI/Swagger documentation

### Active Directory Integration
- Authenticate investigators via Active Directory / LDAP
- Pull AD user accounts and groups as evidence context
- Correlate event log usernames against AD records

---

## 🚀 v3.1.0 — Cloud & Container Forensics (Planned 2027)

Modern infrastructure forensics for cloud-native environments.

- **AWS/Azure/GCP artifact collection** — CloudTrail, VPC Flow Logs, Azure Activity Logs
- **Docker forensics** — Analyze container images and running container artifacts
- **Kubernetes forensics** — Pod logs, config maps, secrets analysis
- **S3/Blob storage forensics** — Analyze cloud storage access logs
- **Lambda/Function log analysis** — Serverless execution trail reconstruction

---

## 🚀 v4.0.0 — AI-Native Platform (Planned 2028)

Full AI integration throughout the investigation workflow.

### Autonomous Investigation Mode
- AI agent that runs a full investigation autonomously
- Ingests evidence, runs all modules, correlates findings, generates report
- Human review and approval workflow before finalizing
- Confidence scoring on all AI findings

### Local LLM Fine-tuning
- Fine-tuned model specifically trained on forensics data
- Runs 100% offline — no API keys, no internet required
- Trained on malware reports, incident reports, CVE descriptions
- Identifies attack patterns the generic models miss

### Natural Language Queries
- Ask questions in plain English: "Show me all files modified after the login event"
- AI translates to database queries and filters results
- Cross-module correlation: "Find any network connection made by the suspicious process"

### Predictive Threat Scoring
- ML model trained on known attack patterns
- Scores every finding by likelihood of malicious intent
- Learns from investigator feedback over time
- Prioritizes what to investigate first

### AI-Generated Court Reports
- Structured reports meeting legal evidentiary standards
- Automatic chain-of-custody documentation
- Expert witness summary generation
- Jurisdiction-aware formatting (US Federal, UK, EU standards)

---

## 🚀 vN — Long-term Vision

- **Mobile forensics** — iOS and Android artifact extraction and analysis
- **Vehicle forensics** — ECU data, infotainment system artifacts, GPS history
- **IoT forensics** — Smart home device logs, firmware extraction
- **Blockchain analysis** — Trace cryptocurrency transactions in financial crime cases
- **Steganography detection** — Hidden data in images, audio, documents
- **Anti-forensics detection** — Detect evidence of log clearing, timestamp manipulation, secure deletion
- **Certified forensics** — ISO 27037 compliant acquisition workflows
- **Cross-platform** — Linux and macOS support

---

## Summary Table

| Version | Theme | Status |
|---------|-------|--------|
| v1.0.0 | Foundation — core 9 modules | ✅ Shipped |
| v1.1.0 | Stability & Polish | 🔄 Planned Q3 2025 |
| v1.2.0 | Reporting & Intelligence | 🔄 Planned Q4 2025 |
| v2.0.0 | Timeline, Disk Images, Registry | 🔄 Planned 2026 |
| v2.1.0 | Browser & Email Forensics | 🔄 Planned 2026 |
| v3.0.0 | Enterprise & Collaboration | 🔄 Planned 2027 |
| v3.1.0 | Cloud & Container Forensics | 🔄 Planned 2027 |
| v4.0.0 | AI-Native Platform | 🔄 Planned 2028 |
| vN | Mobile, IoT, Blockchain, Cross-platform | 🔮 Future |
