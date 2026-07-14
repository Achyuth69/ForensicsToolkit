#pragma once
#include <QWidget>
#include <QFrame>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QScrollArea>
#include <QVBoxLayout>
#include <memory>
#include "AiAssistant.h"

namespace Forensic::UI {

// ── ChatBubble ────────────────────────────────────────────────────────────────
class ChatBubble : public QFrame {
    Q_OBJECT
public:
    enum class Role { User, Assistant, System };
    ChatBubble(Role role, const QString &text, QWidget *parent = nullptr);
    void appendText(const QString &text);

private:
    QLabel *m_textLabel {nullptr};
    Role    m_role;
};

// ── AiAssistantView ───────────────────────────────────────────────────────────
class AiAssistantView : public QWidget {
    Q_OBJECT
public:
    explicit AiAssistantView(QWidget *parent = nullptr);
    void setEvidenceContext(const QJsonObject &ctx);

signals:
    void reportGenerated(const QString &reportText);

private slots:
    void onSendMessage();
    void onGenerateReport();
    void onStreamChunk  (const QString &chunk);
    void onResponseReady(const Forensic::Modules::InvestigationReport &report);
    void onError        (const QString &error);
    void onOpenSettings();
    void onClearChat();
    void onExportChat();

private:
    void setupUi();
    void setupConfigPanel();
    void setupChatArea();
    void setupInputArea();
    void addBubble   (ChatBubble::Role role, const QString &text);
    void scrollToBottom();
    bool validateConfig();

    QScrollArea  *m_chatScroll     {nullptr};
    QWidget      *m_chatContainer  {nullptr};
    QVBoxLayout  *m_chatLayout     {nullptr};
    QLineEdit    *m_inputEdit      {nullptr};
    QComboBox    *m_modelCombo     {nullptr};
    QLabel       *m_statusLabel    {nullptr};
    ChatBubble   *m_streamBubble   {nullptr};

    std::unique_ptr<Forensic::Modules::AiAssistant> m_ai;
    QJsonObject m_evidenceContext;
};

} // namespace Forensic::UI
