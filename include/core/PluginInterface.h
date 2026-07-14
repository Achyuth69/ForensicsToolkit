#pragma once
#include <QString>
#include <QVariantMap>
#include <QJsonObject>
#include <QFileInfo>
#include <memory>

namespace Forensic::Core {

enum class PluginType { Analyzer, Reporter, Importer, Exporter };

struct PluginMeta {
    QString    id;
    QString    name;
    QString    version;
    QString    author;
    QString    description;
    PluginType type;
};

// ── Base plugin interface ─────────────────────────────────────────────────────
class IPlugin {
public:
    virtual ~IPlugin() = default;
    virtual PluginMeta meta()                                    const = 0;
    virtual bool       initialize(const QVariantMap &config)           = 0;
    virtual void       shutdown()                                      = 0;
};

// ── Analyzer plugin interface ─────────────────────────────────────────────────
class IAnalyzerPlugin : public IPlugin {
public:
    virtual QJsonObject analyze(const QString &targetPath,
                                const QVariantMap &options)            = 0;
    virtual int         progressPercent()                        const = 0;
    virtual bool        supportsTarget(const QString &path)      const = 0;
};

} // namespace Forensic::Core
