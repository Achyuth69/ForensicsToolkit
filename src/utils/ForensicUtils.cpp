#include "ForensicUtils.h"
#include <QRegularExpression>

namespace Forensic::Utils {

QString formatBytes(qint64 bytes) {
    if (bytes < 0)             return "N/A";
    if (bytes < 1024)          return QString("%1 B").arg(bytes);
    if (bytes < 1024*1024)     return QString("%1 KB").arg(bytes/1024.0, 0, 'f', 1);
    if (bytes < 1024*1024*1024)return QString("%1 MB").arg(bytes/1024.0/1024.0, 0, 'f', 2);
    return QString("%1 GB").arg(bytes/1024.0/1024.0/1024.0, 0, 'f', 2);
}

QString formatTimestamp(const QDateTime &dt) {
    if (!dt.isValid()) return "Unknown";
    return dt.toString("yyyy-MM-dd  hh:mm:ss  (ddd)");
}

QString truncate(const QString &s, int maxLen) {
    if (s.length() <= maxLen) return s;
    return s.left(maxLen - 3) + "...";
}

QString sanitizeFilename(const QString &name) {
    QString result = name;
    static QRegularExpression illegal(R"([\\/:*?"<>|])");
    result.replace(illegal, "_");
    return result.trimmed();
}

QString hexDump(const QByteArray &data, int maxBytes) {
    QString out;
    int limit = qMin(data.size(), maxBytes);
    for (int i = 0; i < limit; i += 16) {
        out += QString("%1  ").arg(i, 8, 16, QLatin1Char('0'));
        QString ascii;
        for (int j = 0; j < 16; j++) {
            if (i + j < limit) {
                unsigned char c = static_cast<unsigned char>(data[i+j]);
                out += QString("%1 ").arg(c, 2, 16, QLatin1Char('0'));
                ascii += (c >= 0x20 && c < 0x7F) ? QChar(c) : QChar('.');
            } else {
                out += "   ";
                ascii += ' ';
            }
            if (j == 7) out += ' ';
        }
        out += "  " + ascii + "\n";
    }
    if (data.size() > maxBytes)
        out += QString("... (%1 more bytes)\n").arg(data.size() - maxBytes);
    return out;
}

bool isValidIpv4(const QString &ip) {
    static QRegularExpression re(
        R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
    auto m = re.match(ip);
    if (!m.hasMatch()) return false;
    for (int i = 1; i <= 4; i++) {
        int v = m.captured(i).toInt();
        if (v < 0 || v > 255) return false;
    }
    return true;
}

QString threatLabel(int score) {
    if (score <= 0)   return "None";
    if (score < 25)   return "Low";
    if (score < 50)   return "Medium";
    if (score < 75)   return "High";
    return "Critical";
}

} // namespace Forensic::Utils
