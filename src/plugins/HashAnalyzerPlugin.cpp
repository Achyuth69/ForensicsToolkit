/**
 * HashAnalyzerPlugin — Sample ForensicToolkit Analyzer Plugin
 *
 * Demonstrates implementing IAnalyzerPlugin.
 * Computes all three hashes for every file in a target directory
 * and returns a JSON summary.
 */

#include "PluginInterface.h"
#include "HashEngine.h"
#include <QDir>
#include <QDirIterator>
#include <QJsonArray>
#include <QJsonObject>

using namespace Forensic::Core;

class HashAnalyzerPlugin : public IAnalyzerPlugin {
public:
    PluginMeta meta() const override {
        return {
            "forensic.plugins.hash_analyzer",
            "Hash Analyzer",
            "1.0.0",
            "ForensicToolkit",
            "Computes MD5/SHA1/SHA256 for all files in a target directory",
            PluginType::Analyzer
        };
    }

    bool initialize(const QVariantMap &config) override {
        m_maxFileSizeMB = config.value("maxFileSizeMB", 256).toInt();
        return true;
    }

    void shutdown() override {}

    QJsonObject analyze(const QString &targetPath,
                        const QVariantMap &/*options*/) override {
        m_progress = 0;
        QJsonArray results;

        QDirIterator it(targetPath,
                        QDir::Files | QDir::NoDotAndDotDot,
                        QDirIterator::Subdirectories);

        QStringList files;
        while (it.hasNext()) files.append(it.next());

        int total = files.size();
        int done  = 0;

        for (const QString &fp : files) {
            QFileInfo fi(fp);
            if (fi.size() > static_cast<qint64>(m_maxFileSizeMB) * 1024 * 1024) {
                results.append(QJsonObject{
                    {"path",   fp},
                    {"status", "skipped_too_large"},
                    {"size",   fi.size()}
                });
            } else {
                auto h = HashEngine::computeAll(fp);
                results.append(QJsonObject{
                    {"path",   fp},
                    {"md5",    h.md5},
                    {"sha1",   h.sha1},
                    {"sha256", h.sha256},
                    {"size",   fi.size()},
                    {"valid",  h.valid}
                });
            }
            m_progress = (++done * 100) / qMax(1, total);
        }

        QJsonObject result;
        result["plugin"]     = meta().name;
        result["targetPath"] = targetPath;
        result["totalFiles"] = total;
        result["results"]    = results;
        return result;
    }

    int  progressPercent() const override { return m_progress; }

    bool supportsTarget(const QString &path) const override {
        // Supports any directory
        return QFileInfo(path).isDir();
    }

private:
    int m_progress{0};
    int m_maxFileSizeMB{256};
};

// Export factory function for dynamic loading
extern "C" IAnalyzerPlugin* createPlugin() {
    return new HashAnalyzerPlugin();
}
