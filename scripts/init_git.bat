@echo off
REM ============================================================
REM  ForensicToolkit — Git Repository Initializer
REM ============================================================
echo Initializing Git repository...

git init
git add .gitignore
git add CMakeLists.txt vcpkg.json README.md BUILDING.md CHANGELOG.md LICENSE
git add cmake\ scripts\ docs\
git add include\ src\ tests\ resources\
git add third_party\

git commit -m "Initial commit: ForensicToolkit v1.0.0

Enterprise Digital Forensics Investigation Toolkit

Modules:
- Case Management (SQLite persistence)
- File System Analyzer (recursive scan, hashing, duplicates)
- File Integrity Module (baseline + tamper detection)
- Memory Analyzer (dump image parsing, string extraction)
- Network Forensics (native PCAP parser)
- Windows Event Log Parser (EVTX/XML)
- Malware Detector (YARA-compatible engine)
- AI Investigation Assistant (OpenAI/Anthropic/Ollama)
- Report Generator (PDF/HTML/JSON)
- Dark theme Qt6 UI with charts and dashboard

Stack: C++17, Qt6, OpenSSL, SQLite
Tests: 7 test suites (unit + integration)"

echo.
echo [SUCCESS] Git repository initialized with initial commit.
echo Use 'git log --oneline' to verify.
