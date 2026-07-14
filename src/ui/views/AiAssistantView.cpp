#include "AiAssistantView.h"
#include "SettingsDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QScrollBar>
#include <QKeyEvent>
#include <QFileDialog>
#include <QTextStream>
#include <QMessageBox>
#include <QTimer>
#include <QSettings>
#include <QJsonDocument>

namespace Forensic::UI {

// ─── ChatBubble ───────────────────────────────────────────────────────────────
ChatBubble::ChatBubble(Role role, const QString &text, QWidget *parent)
    : QFrame(parent), m_role(role)
{
    setObjectName("ChatBubble");
    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(8, 6, 8, 6);

    m_textLabel = new QLabel(this);
    m_textLabel->setWordWrap(true);
    m_textLabel->setTextFormat(Qt::PlainText);
    m_textLabel->setText(text);
    m_textLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);

    QString bgColor, textColor, align;
    if (role == Role::User) {
        bgColor   = "#313244";
        textColor = "#cdd6f4";
        align     = "right";
        layout->addStretch();
        layout->addWidget(m_textLabel);
    } else if (role == Role::Assistant) {
        bgColor   = "#262637";
        textColor = "#a6e3a1";
        align     = "left";
        layout->addWidget(m_textLabel);
        layout->addStretch();
    } else {
        bgColor   = "#1e1e2e";
        textColor = "#6c7086";
        layout->addWidget(m_textLabel);
        layout->addStretch();
    }

    setStyleSheet(QString(
        "#ChatBubble { background: %1; border-radius: 10px; margin: 3px 20px; }"
        "QLabel { color: %2; font-size: 13px; line-height: 1.5; }")
        .arg(bgColor, textColor));
}

void ChatBubble::appendText(const QString &text) {
    m_textLabel->setText(m_textLabel->text() + text);
}

// ─── AiAssistantView ─────────────────────────────────────────────────────────
AiAssistantView::AiAssistantView(QWidget *parent) : QWidget(parent) {
    m_ai = std::make_unique<Forensic::Modules::AiAssistant>(this);

    connect(m_ai.get(), &Forensic::Modules::AiAssistant::responseReady,
            this, &AiAssistantView::onResponseReady);
    connect(m_ai.get(), &Forensic::Modules::AiAssistant::streamChunk,
            this, &AiAssistantView::onStreamChunk);
    connect(m_ai.get(), &Forensic::Modules::AiAssistant::errorOccurred,
            this, &AiAssistantView::onError);
    connect(m_ai.get(), &Forensic::Modules::AiAssistant::requestStarted, this, [this]{
        m_statusLabel->setText("🤖 Thinking...");
        m_streamBubble = nullptr;
    });
    connect(m_ai.get(), &Forensic::Modules::AiAssistant::requestFinished, this, [this]{
        m_statusLabel->setText("Ready");
    });

    setupUi();
}

void AiAssistantView::setupUi() {
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0,0,0,0);
    layout->setSpacing(0);

    // Header
    auto *header = new QWidget(this);
    header->setStyleSheet("background:#181825;border-bottom:1px solid #45475a;");
    auto *hl = new QHBoxLayout(header);
    hl->setContentsMargins(16,10,16,10);
    auto *title = new QLabel("🤖  AI Investigation Assistant", header);
    title->setStyleSheet("font-size:16px;font-weight:bold;color:#89b4fa;");
    hl->addWidget(title,1);
    auto *settingsBtn = new QPushButton("⚙ API Settings", header);
    auto *clearBtn    = new QPushButton("🗑 Clear Chat", header);
    auto *exportBtn   = new QPushButton("Export Chat", header);
    connect(settingsBtn, &QPushButton::clicked, this, &AiAssistantView::onOpenSettings);
    connect(clearBtn,    &QPushButton::clicked, this, &AiAssistantView::onClearChat);
    connect(exportBtn,   &QPushButton::clicked, this, &AiAssistantView::onExportChat);
    hl->addWidget(settingsBtn);
    hl->addWidget(clearBtn);
    hl->addWidget(exportBtn);
    layout->addWidget(header);

    // Config strip
    setupConfigPanel();

    // Chat area
    setupChatArea();

    // Input area
    setupInputArea();
}

void AiAssistantView::setupConfigPanel() {
    auto *strip = new QWidget(this);
    strip->setStyleSheet("background:#262637;border-bottom:1px solid #45475a;");
    auto *sl = new QHBoxLayout(strip);
    sl->setContentsMargins(12,6,12,6);

    auto *providerLabel = new QLabel("Provider:", strip);
    auto *providerCombo = new QComboBox(strip);
    providerCombo->addItems({"OpenAI","Anthropic","Ollama (Local)","OpenRouter"});

    auto *modelLabel = new QLabel("Model:", strip);
    m_modelCombo = new QComboBox(strip);
    m_modelCombo->addItems({"gpt-4o","gpt-4o-mini","gpt-4-turbo",
                             "claude-3-5-sonnet-20241022","claude-3-haiku-20240307",
                             "llama3.1:70b","llama3.1:8b","mistral:latest"});
    m_modelCombo->setEditable(true);

    auto *reportBtn = new QPushButton("📄 Generate Report", strip);
    reportBtn->setProperty("primary",true);
    m_statusLabel = new QLabel("Configure API key in Settings", strip);
    m_statusLabel->setStyleSheet("color:#a6adc8;font-size:11px;");

    connect(providerCombo, &QComboBox::currentTextChanged, this, [this, providerCombo]{
        Forensic::Modules::AiConfig cfg = m_ai->config();
        QString p = providerCombo->currentText().toLower();
        if (p.contains("openai"))       cfg.provider = "openai";
        else if (p.contains("anthropic")) cfg.provider = "anthropic";
        else if (p.contains("ollama"))  { cfg.provider = "ollama"; cfg.baseUrl = "http://localhost:11434/v1/chat/completions"; }
        else if (p.contains("openrouter")) cfg.provider = "openrouter";
        m_ai->setConfig(cfg);
    });

    connect(m_modelCombo, &QComboBox::currentTextChanged, this, [this]{
        auto cfg = m_ai->config();
        cfg.model = m_modelCombo->currentText();
        m_ai->setConfig(cfg);
    });

    connect(reportBtn, &QPushButton::clicked, this, &AiAssistantView::onGenerateReport);

    sl->addWidget(providerLabel);
    sl->addWidget(providerCombo);
    sl->addWidget(modelLabel);
    sl->addWidget(m_modelCombo);
    sl->addWidget(reportBtn);
    sl->addStretch();
    sl->addWidget(m_statusLabel);

    static_cast<QVBoxLayout*>(layout())->addWidget(strip);
}

void AiAssistantView::setupChatArea() {
    m_chatScroll = new QScrollArea(this);
    m_chatScroll->setWidgetResizable(true);
    m_chatScroll->setStyleSheet("QScrollArea { border: none; background: #1e1e2e; }");

    m_chatContainer = new QWidget(m_chatScroll);
    m_chatContainer->setStyleSheet("background: #1e1e2e;");
    m_chatLayout = new QVBoxLayout(m_chatContainer);
    m_chatLayout->setContentsMargins(12,12,12,12);
    m_chatLayout->setSpacing(8);
    m_chatLayout->addStretch();

    m_chatScroll->setWidget(m_chatContainer);

    // Welcome message
    addBubble(ChatBubble::Role::System,
        "👋  Welcome to ForensicAI. I'm your AI investigation assistant.\n"
        "Upload forensic evidence, ask questions about your case, or click "
        "'Generate Report' to create a comprehensive investigation summary.\n"
        "Configure your API key in ⚙ API Settings to get started.");

    static_cast<QVBoxLayout*>(layout())->addWidget(m_chatScroll, 1);
}

void AiAssistantView::setupInputArea() {
    auto *inputArea = new QWidget(this);
    inputArea->setStyleSheet("background:#181825;border-top:1px solid #45475a;");
    auto *il = new QHBoxLayout(inputArea);
    il->setContentsMargins(12,10,12,10);

    m_inputEdit = new QLineEdit(inputArea);
    m_inputEdit->setPlaceholderText("Ask a question about the forensic evidence...");
    m_inputEdit->installEventFilter(this);

    auto *sendBtn = new QPushButton("Send ↵", inputArea);
    sendBtn->setProperty("primary", true);
    sendBtn->setFixedWidth(90);

    connect(sendBtn, &QPushButton::clicked, this, &AiAssistantView::onSendMessage);
    connect(m_inputEdit, &QLineEdit::returnPressed, this, &AiAssistantView::onSendMessage);

    il->addWidget(m_inputEdit, 1);
    il->addWidget(sendBtn);

    static_cast<QVBoxLayout*>(layout())->addWidget(inputArea);
}

void AiAssistantView::setEvidenceContext(const QJsonObject &ctx) {
    m_evidenceContext = ctx;
}

void AiAssistantView::onSendMessage() {
    QString text = m_inputEdit->text().trimmed();
    if (text.isEmpty()) return;
    m_inputEdit->clear();

    if (!validateConfig()) return;

    addBubble(ChatBubble::Role::User, text);
    m_ai->askQuestion(text, m_evidenceContext);
}

void AiAssistantView::onGenerateReport() {
    if (!validateConfig()) return;
    addBubble(ChatBubble::Role::System, "Generating comprehensive investigation report...");
    m_ai->generateExecutiveReport(m_evidenceContext);
}

void AiAssistantView::onStreamChunk(const QString &chunk) {
    if (!m_streamBubble) {
        m_streamBubble = new ChatBubble(ChatBubble::Role::Assistant, "", m_chatContainer);
        m_chatLayout->insertWidget(m_chatLayout->count() - 1, m_streamBubble);
    }
    m_streamBubble->appendText(chunk);
    scrollToBottom();
}

void AiAssistantView::onResponseReady(const Forensic::Modules::InvestigationReport &report) {
    m_streamBubble = nullptr;
    if (!report.success) {
        addBubble(ChatBubble::Role::System, "❌ Error: " + report.errorMessage);
        return;
    }

    QString response = report.rawResponse;
    if (response.isEmpty()) response = report.summary;
    addBubble(ChatBubble::Role::Assistant, response);
    emit reportGenerated(report.rawResponse);
    scrollToBottom();
}

void AiAssistantView::onError(const QString &error) {
    addBubble(ChatBubble::Role::System, "❌ " + error);
    m_statusLabel->setText("Error");
}

void AiAssistantView::onOpenSettings() {
    SettingsDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        // Settings dialog updates QSettings; reload AI config
        QSettings s("ForensicToolkit","ForensicToolkit");
        Forensic::Modules::AiConfig cfg;
        cfg.apiKey   = s.value("ai/apiKey").toString();
        cfg.provider = s.value("ai/provider","openai").toString();
        cfg.model    = s.value("ai/model","gpt-4o").toString();
        cfg.baseUrl  = s.value("ai/baseUrl").toString();
        m_ai->setConfig(cfg);
        m_statusLabel->setText(cfg.apiKey.isEmpty() ? "No API key" : "✓ API configured");
    }
}

void AiAssistantView::onClearChat() {
    while (m_chatLayout->count() > 1) {
        auto *item = m_chatLayout->takeAt(0);
        if (item->widget()) item->widget()->deleteLater();
        delete item;
    }
    m_streamBubble = nullptr;
}

void AiAssistantView::onExportChat() {
    QString path = QFileDialog::getSaveFileName(this,"Export Chat","","Text (*.txt)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return;
    QTextStream ts(&f);
    for (int i = 0; i < m_chatLayout->count(); i++) {
        auto *w = m_chatLayout->itemAt(i)->widget();
        if (auto *bubble = qobject_cast<ChatBubble*>(w)) {
            auto *lbl = bubble->findChild<QLabel*>();
            if (lbl) ts << lbl->text() << "\n\n";
        }
    }
}

void AiAssistantView::addBubble(ChatBubble::Role role, const QString &text) {
    auto *bubble = new ChatBubble(role, text, m_chatContainer);
    m_chatLayout->insertWidget(m_chatLayout->count() - 1, bubble);
    scrollToBottom();
}

void AiAssistantView::scrollToBottom() {
    QTimer::singleShot(50, m_chatScroll, [this]{
        m_chatScroll->verticalScrollBar()->setValue(
            m_chatScroll->verticalScrollBar()->maximum());
    });
}

bool AiAssistantView::validateConfig() {
    if (!m_ai->isConfigured()) {
        addBubble(ChatBubble::Role::System,
            "⚠ Please configure your API key in ⚙ API Settings before sending messages.");
        return false;
    }
    return true;
}

} // namespace Forensic::UI
