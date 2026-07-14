#pragma once
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>

namespace Forensic::Modules {

struct AiConfig {
    QString provider;       // "openai" | "anthropic" | "ollama" | "openrouter"
    QString apiKey;
    QString model;          // e.g. "gpt-4o", "claude-3-5-sonnet"
    QString baseUrl;        // for custom/local endpoints
    int     maxTokens{4096};
    double  temperature{0.2};
};

struct InvestigationReport {
    QString summary;
    QString attackTimeline;
    QString iocExplanation;
    QString recommendedActions;
    QString executiveSummary;
    QString riskRating;
    QString rawResponse;
    bool    success{false};
    QString errorMessage;
};

class AiAssistant : public QObject {
    Q_OBJECT
public:
    explicit AiAssistant(QObject *parent = nullptr);
    ~AiAssistant() override;

    void setConfig(const AiConfig &config);
    AiConfig config() const { return m_config; }

    // Analyze forensic evidence context and generate report
    void analyzeEvidence(const QJsonObject &evidenceContext);

    // Ask a specific question about the evidence
    void askQuestion(const QString &question, const QJsonObject &context);

    // Generate executive report
    void generateExecutiveReport(const QJsonObject &fullCaseData);

    bool isConfigured() const;
    void cancelRequest();

signals:
    void responseReady(const InvestigationReport &report);
    void streamChunk(const QString &chunk);
    void errorOccurred(const QString &error);
    void requestStarted();
    void requestFinished();

private slots:
    void onReplyFinished();
    void onReadyRead();
    void onSslErrors(const QList<QSslError> &errors);

private:
    QString buildSystemPrompt() const;
    QString buildUserPrompt(const QJsonObject &context) const;
    QJsonObject buildRequestPayload(const QString &systemPrompt,
                                     const QString &userPrompt) const;
    void sendRequest(const QJsonObject &payload);
    InvestigationReport parseResponse(const QByteArray &responseData);

    AiConfig              m_config;
    QNetworkAccessManager m_nam;
    QNetworkReply        *m_reply{nullptr};
    QByteArray            m_buffer;
};

} // namespace Forensic::Modules
