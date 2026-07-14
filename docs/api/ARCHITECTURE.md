# ForensicToolkit — Architecture Guide

## Overview

ForensicToolkit follows a layered, modular architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                        Qt UI Layer                          │
│  MainWindow ─── Views ─── Dialogs ─── Widgets              │
└──────────────────────┬──────────────────────────────────────┘
                       │ signals / slots
┌──────────────────────▼──────────────────────────────────────┐
│                    Service Layer                             │
│              CaseService (business logic)                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                  Repository Layer                            │
│           CaseRepository (SQLite / Qt SQL)                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Module Layer                              │
│  FileSystemAnalyzer │ FileIntegrityModule │ MemoryAnalyzer  │
│  NetworkForensics   │ EventLogParser      │ MalwareDetector │
│  AiAssistant        │ ReportGenerator                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                     Core Layer                               │
│  ForensicCase │ HashEngine │ Logger │ ThreadPool             │
│  PluginInterface                                             │
└─────────────────────────────────────────────────────────────┘
```

## Threading Model

Every analysis module that processes large files runs on `QtConcurrent::run()`.  
Signals are emitted and marshalled back to the UI thread via `Qt::QueuedConnection`.

```
UI Thread                      Worker Thread
    │                               │
    │── QtConcurrent::run() ──────►│
    │                               │ analyzeImage()
    │◄── progressChanged(pct) ─────│   (every N files)
    │◄── fileFound(entry) ─────────│
    │◄── scanComplete(summary) ────│
```

## Data Flow: Full Investigation

```
1. UI: NewCaseDialog  ──►  CaseService::createCase()  ──►  CaseRepository::insert()
2. UI: AddEvidenceDialog ─► CaseService::addEvidence() ─► HashEngine::computeAll()
3. UI: FileSystemView ──►  FileSystemAnalyzer::scanDirectory()  [Worker Thread]
                       ──►  signals → UI updates
4. UI: MalwareView    ──►  MalwareDetector::scanDirectory()     [Worker Thread]
5. UI: AiAssistantView ──► AiAssistant::analyzeEvidence()      [QNetworkAccessManager]
6. UI: ReportView     ──►  ReportGenerator::generate()
                       ──►  PDF (QPrinter) | HTML (QTextDocument) | JSON (QJsonDocument)
```

## Module Design Pattern

Every analysis module follows the same pattern:

```cpp
class SomeAnalyzer : public QObject {
    Q_OBJECT
public:
    void analyze(const QString &target);  // starts async operation
    void cancel();                         // thread-safe cancellation
    const ResultType& result() const;      // results after completion
    QJsonObject toJson() const;            // serialise results

signals:
    void progressChanged(int pct, const QString &status);
    void analysisComplete(const ResultType &result);
    void errorOccurred(const QString &error);

private:
    std::atomic<bool> m_cancelled{false};
    ResultType        m_result;
};
```

## Database Schema

```sql
cases (id, title, description, case_number, status, created_at, updated_at, report_path)
investigators (id, case_id, name, email, badge, role, assigned_at)
evidence (id, case_id, label, file_path, hash, type, size_bytes,
          acquired_at, acquired_by, chain_of_custody, verified)
notes (id, case_id, author_id, content, created_at, updated_at)
```

All tables use UUID primary keys. Foreign keys with `ON DELETE CASCADE`.
WAL journal mode for concurrent reads.
