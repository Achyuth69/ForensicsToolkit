#pragma once
// SQLite3 stub - ForensicToolkit uses Qt SQL (QSQLITE driver) at runtime.
// This header is only needed if direct sqlite3_* C API calls are made.
// The project uses QSqlDatabase/QSqlQuery exclusively, so this stub satisfies
// any transitive include without pulling in the full amalgamation.
#ifndef SQLITE3_H
#define SQLITE3_H
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef long long sqlite3_int64;
typedef unsigned long long sqlite3_uint64;
#define SQLITE_OK   0
#define SQLITE_ERROR 1
#define SQLITE_ROW  100
#define SQLITE_DONE 101
#ifdef __cplusplus
}
#endif
#endif /* SQLITE3_H */
