#pragma once
#include <QString>
#include <QDateTime>
#include <QByteArray>

namespace Forensic::Utils {

// Format a byte count as human-readable (KB, MB, GB)
QString formatBytes(qint64 bytes);

// Format a datetime as investigation-style string
QString formatTimestamp(const QDateTime &dt);

// Truncate a string to maxLen, adding ellipsis
QString truncate(const QString &s, int maxLen = 60);

// Sanitize a filename (strip illegal characters)
QString sanitizeFilename(const QString &name);

// Hex-dump the first n bytes of data
QString hexDump(const QByteArray &data, int maxBytes = 256);

// Return true if the string looks like a valid IPv4
bool isValidIpv4(const QString &ip);

// Convert a threat score (0-100) to a label
QString threatLabel(int score);

} // namespace Forensic::Utils
