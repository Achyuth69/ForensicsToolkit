#include "AiAssistant.h"
#include "Logger.h"
#include <QJsonDocument>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QSslConfiguration>
#include <QRegularExpression>
#include <QUrl>


namespace Forensic::Modules {

AiAssistant::AiAssistant(QObject *parent) : QObject(parent) {
    connect(&m_nam, &QNetworkAccessManager::finished, this, &AiAssistant::onReplyFinished);
}

AiAssistant::~AiAssistant() {
    cancelRequest();
}

void AiAssistant::setConfig(const AiConfig &config) {
    m_config = config;
}

bool AiAssistant::isConfigured() const {
    return !m_config.apiKey.isEmpty() || !m_config.baseUrl.isEmpty();
}

void AiAssistant::analyzeEvidence(const QJsonObject &evidenceContext) {
    if (!isConfigured()) {
        emit errorOccurred("AI Assistant is not configured. Please add your API key in Settings.");
        return;
    }

    QString system = buildSystemPrompt();
    QString user   = "Analyze the following forensic evidence and provide a detailed investigation report:\n\n"
                   + QString::fromUtf8(QJsonDocument(evidenceContext).toJson(QJsonDocument::Indented));

    auto payload = buildRequestPayload(system, user);
    emit requestStarted();
    sendRequest(payload);
}

void AiAssistant::askQuestion(const QString &question, const QJsonObject &context) {
    if (!isConfigured()) {
        emit errorOccurred("AI Assistant is not configured.");
        return;
    }

    QString system = buildSystemPrompt();
    QString user   = question;
    if (!context.isEmpty()) {
        user += "\n\nContext:\n" + QString::fromUtf8(
            QJsonDocument(context).toJson(QJsonDocument::Compact));
    }

    auto payload = buildRequestPayload(system, user);
    emit requestStarted();
    sendRequest(payload);
}

void AiAssistant::generateExecutiveReport(const QJsonObject &fullCaseData) {
    if (!isConfigured()) {
        emit errorOccurred("AI Assistant is not configured.");
        return;
    }

    QString system = buildSystemPrompt();
    QString user   = R"(Generate a comprehensive executive forensic investigation report for the following case data.
Structure it with these sections:
1. EXECUTIVE SUMMARY
2. ATTACK TIMELINE
3. INDICATORS OF COMPROMISE (IOCs)
4. TECHNICAL FINDINGS
5. RECOMMENDED ACTIONS
6. CONCLUSION

Case data:
)" + QString::fromUtf8(QJsonDocument(fullCaseData).toJson(QJsonDocument::Indented));

    auto payload = buildRequestPayload(system, user);
    emit requestStarted();
    sendRequest(payload);
}

void AiAssistant::cancelRequest() {
    if (m_reply) {
        m_reply->abort();
        m_reply->deleteLater();
        m_reply = nullptr;
    }
}

QString AiAssistant::buildSystemPrompt() const {
    return R"(You are ForensicAI, an expert digital forensics investigator and malware analyst.
You have deep expertise in:
- Windows/Linux forensics, memory analysis, and disk forensics
- Network traffic analysis (PCAP, DNS, HTTP)
- Malware analysis, reverse engineering, and threat intelligence
- Incident response and attack reconstruction
- Writing professional forensic investigation reports

When analyzing evidence:
- Be precise, factual, and structured
- Identify attack patterns, TTPs (Tactics, Techniques, Procedures)
- Map findings to MITRE ATT&CK framework when applicable
- Highlight critical indicators of compromise (IOCs)
- Provide actionable remediation recommendations
- Use professional forensic report language
- Assign confidence levels to findings (High/Medium/Low)

Always structure your response with clear section headers.)";
}

QString AiAssistant::buildUserPrompt(const QJsonObject &context) const {
    return QString::fromUtf8(QJsonDocument(context).toJson(QJsonDocument::Indented));
}

QJsonObject AiAssistant::buildRequestPayload(const QString &systemPrompt,
                                               const QString &userPrompt) const {
    QJsonObject sysMsg, userMsg;
    sysMsg["role"]    = "system";
    sysMsg["content"] = systemPrompt;
    userMsg["role"]   = "user";
    userMsg["content"] = userPrompt;
    QJsonArray messages;
    messages.append(sysMsg);
    messages.append(userMsg);

    QJsonObject result;
    result["model"]       = m_config.model.isEmpty() ? "gpt-4o" : m_config.model;
    result["messages"]    = messages;
    result["max_tokens"]  = m_config.maxTokens;
    result["temperature"] = m_config.temperature;
    result["stream"]      = false;
    return result;
}

void AiAssistant::sendRequest(const QJsonObject &payload) {
    QString url = m_config.baseUrl;
    if (url.isEmpty()) {
        if (m_config.provider == "anthropic")
            url = "https://api.anthropic.com/v1/messages";
        else if (m_config.provider == "openrouter")
            url = "https://openrouter.ai/api/v1/chat/completions";
        else if (m_config.provider == "ollama")
            url = "http://localhost:11434/api/chat";
        else
            url = "https://api.openai.com/v1/chat/completions";
    }

    QNetworkRequest req;
    req.setUrl(QUrl(url));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    if (m_config.provider == "anthropic") {
        req.setRawHeader("x-api-key",            m_config.apiKey.toUtf8());
        req.setRawHeader("anthropic-version",    "2023-06-01");
    } else {
        req.setRawHeader("Authorization", ("Bearer " + m_config.apiKey).toUtf8());
    }
    req.setRawHeader("User-Agent", "ForensicToolkit/1.0");

    m_buffer.clear();
    m_reply = m_nam.post(req, QJsonDocument(payload).toJson(QJsonDocument::Compact));

    connect(m_reply, &QNetworkReply::readyRead, this, &AiAssistant::onReadyRead);
    connect(m_reply, &QNetworkReply::sslErrors, this, &AiAssistant::onSslErrors);
}

void AiAssistant::onReadyRead() {
    if (m_reply) {
        QByteArray chunk = m_reply->readAll();
        m_buffer.append(chunk);
        // Try to emit stream chunks for SSE
        QString text = QString::fromUtf8(chunk);
        if (!text.trimmed().isEmpty()) emit streamChunk(text);
    }
}

void AiAssistant::onReplyFinished() {
    emit requestFinished();
    if (!m_reply) return;

    QNetworkReply::NetworkError err = m_reply->error();
    if (err != QNetworkReply::NoError) {
        QString errMsg = m_reply->errorString();
        m_reply->deleteLater();
        m_reply = nullptr;
        emit errorOccurred("Network error: " + errMsg);
        return;
    }

    QByteArray responseData = m_buffer.isEmpty() ? m_reply->readAll() : m_buffer;
    m_reply->deleteLater();
    m_reply = nullptr;

    InvestigationReport report = parseResponse(responseData);
    emit responseReady(report);
}

void AiAssistant::onSslErrors(const QList<QSslError> &errors) {
    for (const auto &e : errors)
        LOG_WARN("SSL error: " + e.errorString());
}

InvestigationReport AiAssistant::parseResponse(const QByteArray &responseData) {
    InvestigationReport report;
    report.rawResponse = QString::fromUtf8(responseData);

    QJsonDocument doc = QJsonDocument::fromJson(responseData);
    if (doc.isNull()) {
        report.errorMessage = "Invalid JSON response from AI provider";
        return report;
    }

    QJsonObject obj = doc.object();

    // OpenAI / OpenRouter format
    if (obj.contains("choices")) {
        QJsonArray choices = obj["choices"].toArray();
        if (!choices.isEmpty()) {
            QJsonObject msg = choices[0].toObject()["message"].toObject();
            QString content = msg["content"].toString();
            report.rawResponse = content;
            report.success     = true;

            // Parse structured sections
            auto extractSection = [&](const QString &header) -> QString {
                QStringList headers = {
                    header + "\n", header + ":\n",
                    "## " + header, "# " + header,
                    "**" + header + "**"
                };
                for (const QString &h : headers) {
                    int start = content.indexOf(h, 0, Qt::CaseInsensitive);
                    if (start == -1) continue;
                    start += h.length();
                    // Find next section header
                    int end = content.length();
                    QRegularExpression nextSection(R"((\n#{1,3} |\n\*\*[A-Z]))");
                    auto nextMatch = nextSection.match(content, start + 10);
                    if (nextMatch.hasMatch() && nextMatch.capturedStart() > start)
                        end = nextMatch.capturedStart();
                    return content.mid(start, end - start).trimmed();
                }
                return {};
            };

            report.summary            = extractSection("EXECUTIVE SUMMARY");
            if (report.summary.isEmpty()) report.summary = content.left(500);
            report.attackTimeline     = extractSection("ATTACK TIMELINE");
            report.iocExplanation     = extractSection("INDICATORS OF COMPROMISE");
            report.recommendedActions = extractSection("RECOMMENDED ACTIONS");
            report.executiveSummary   = extractSection("CONCLUSION");
        }
    }
    // Anthropic format
    else if (obj.contains("content")) {
        QJsonArray content = obj["content"].toArray();
        if (!content.isEmpty()) {
            QString text = content[0].toObject()["text"].toString();
            report.rawResponse = text;
            report.summary     = text.left(1000);
            report.success     = true;
        }
    }
    // Ollama format
    else if (obj.contains("message")) {
        QString text = obj["message"].toObject()["content"].toString();
        report.rawResponse = text;
        report.summary     = text;
        report.success     = true;
    }

    if (!report.success) {
        report.errorMessage = "Unexpected response format: " + QString::fromUtf8(responseData.left(200));
    }

    return report;
}

} // namespace Forensic::Modules
