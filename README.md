# ForensicToolkit — Enterprise Digital Forensics Investigation Platform

![License](https://img.shields.io/badge/license-MIT-blue)
![C++](https://img.shields.io/badge/C%2B%2B-17-blue)
![Qt](https://img.shields.io/badge/Qt-6-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

🌐 **[Live Demo & Documentation](https://forensictoolkit.achyuth.me)**

A production-quality, modular digital forensics investigation toolkit built with **C++17**, **Qt 6**, **OpenSSL**, and **SQLite**. Comparable in concept to ProDiscover, FTK, and Autopsy — designed as a professional software engineering portfolio project.

---

## Screenshots

| Dashboard | Case Manager | Network Forensics |
|-----------|-------------|-------------------|
| *(dark dashboard with metric cards and charts)* | *(case list + evidence management)* | *(PCAP packet table + protocol charts)* |

---

## Features

| Module | Capabilities |
|--------|-------------|
| **Case Management** | Create/manage forensic cases, investigators, evidence inventory, notes, timeline |
| **File System Analyzer** | Recursive directory scan, hash computation (MD5/SHA1/SHA256), hidden/system file detection, duplicate detection, MIME type identification |
| **File Integrity** | Baseline snapshot creation, tamper detection, modified/renamed/missing file reporting |
| **Memory Analysis** | Import memory dump images, extract strings, process list heuristics, network connections |
| **Network Forensics** | Import PCAP files, parse TCP/UDP/DNS/HTTP/HTTPS/SMTP/FTP, top IPs, suspicious host detection |
| **Event Log Parser** | Parse Windows EVTX / exported XML logs, detect failed logins, USB events, process executions, suspicious activity |
| **Malware Detection** | YARA-compatible rule engine, built-in heuristics, PE analysis, extension mismatch detection, batch scanning |
| **AI Investigation Assistant** | Connects to OpenAI / Anthropic / Ollama / OpenRouter, generates investigation summaries, attack timelines, IOC explanations, executive reports |
| **Report Generator** | Export as **PDF**, **HTML**, or **JSON** with full case data, evidence inventory, network analysis, malware findings, AI summary |
| **Dashboard** | Metric cards (evidence count, threat score, network alerts), charts (threat distribution, protocol breakdown) |

---

## Architecture

```
ForensicToolkit/
├── src/
│   ├── core/               # ForensicCase, Logger, HashEngine, ThreadPool
│   ├── modules/            # One directory per analysis module
│   │   ├── filesystem_analyzer/
│   │   ├── file_integrity/
│   │   ├── memory_analysis/
│   │   ├── network_forensics/
│   │   ├── event_log_parser/
│   │   ├── malware_detection/
│   │   ├── ai_assistant/
│   │   └── report_generator/
│   ├── services/           # CaseService (business logic layer)
│   ├── repositories/       # CaseRepository (SQLite data access layer)
│   ├── ui/
│   │   ├── views/          # MainWindow + one view per module
│   │   ├── dialogs/        # NewCase, AddEvidence, AddInvestigator, Settings
│   │   └── widgets/        # Reusable UI components
│   └── utils/              # ForensicUtils (formatting, validation)
├── include/                # All public headers (mirrors src/ structure)
├── resources/
│   ├── styles/dark.qss     # Catppuccin Mocha dark theme
│   └── yara_rules/         # Built-in YARA detection rules
├── tests/
│   ├── unit/               # QtTest unit tests for every module
│   └── integration/        # End-to-end workflow tests
├── cmake/                  # CMake helper macros
└── scripts/                # Build and deployment scripts
```

**Design patterns used:**
- MVC (Model-View separation via service/repository layers)
- Repository pattern (SQLite abstraction)
- Service layer (business logic decoupled from UI)
- Observer / Signal-Slot (Qt signals throughout)
- Plugin interface (IAnalyzerPlugin for extensibility)
- Thread pool (multi-threaded scans via QThreadPool / QtConcurrent)

---

## Requirements

| Dependency | Version | Notes |
|-----------|---------|-------|
| CMake | ≥ 3.21 | |
| Qt | 6.5+ | Core, Widgets, Network, Sql, Charts, PrintSupport, Concurrent, Xml |
| OpenSSL | 1.1.1 / 3.x | For MD5 / SHA1 / SHA256 |
| C++ Compiler | MSVC 2019+ / GCC 11+ / Clang 14+ | C++17 required |

---

## Building

### Windows (MSVC)

```bat
# Set Qt6 path if not auto-detected
set Qt6_DIR=C:\Qt\6.7.0\msvc2019_64\lib\cmake\Qt6

scripts\build_windows.bat
```

### Linux

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install cmake ninja-build libssl-dev qt6-base-dev \
     libqt6charts6-dev libqt6sql6-sqlite

chmod +x scripts/build_linux.sh
./scripts/build_linux.sh
```

### Manual CMake

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build --parallel
```

---

## Running Tests

```bash
cd build
ctest --output-on-failure
```

Unit tests cover: HashEngine, FileSystemAnalyzer, FileIntegrityModule, MalwareDetector, CaseService, ForensicUtils.

---

## AI Assistant Setup

1. Open **Settings** (toolbar or Tools menu)
2. Select your AI provider: OpenAI, Anthropic, OpenRouter, or Ollama (local)
3. Enter your API key
4. Set the model (e.g. `gpt-4o`, `claude-3-5-sonnet-20241022`, `llama3.1:70b`)
5. Click **Save Settings**

The AI assistant will generate investigation summaries, attack timelines, IOC explanations, and executive reports from your forensic evidence data.

---

## Usage Guide

1. **Create a Case**: File → New Case → fill in case title and number
2. **Add Evidence**: In Case Manager → Evidence tab → Add Evidence → select file (hash computed automatically)
3. **Run Analysis**:
   - File System: select a directory, click Scan
   - Network: load a `.pcap` file
   - Memory: load a `.raw` / `.vmem` / `.dmp` file
   - Event Logs: load an `.evtx` or exported `.xml` log
   - Malware: scan a file or directory
4. **AI Report**: AI Assistant → Generate Report
5. **Export**: Reports → choose PDF/HTML/JSON → Generate
6. D:\DESKTOP\DA\Cyber\Project-1\build\bin\ForensicToolkit.exe

---

## YARA Rules

Built-in rules detect:
- Mimikatz / credential dumping tools
- Meterpreter shellcode
- Obfuscated PowerShell
- Ransomware indicators
- PHP webshells
- Registry persistence keys
- Packed executables (UPX, ASPack)
- Office macro malware

Add custom rules by placing `.yar` files in `resources/yara_rules/` or loading them at runtime via the Malware Detection view.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

Built with: [Qt 6](https://www.qt.io), [OpenSSL](https://www.openssl.org), [SQLite](https://www.sqlite.org), [YARA](https://github.com/VirusTotal/yara)
