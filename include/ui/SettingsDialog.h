#pragma once
#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>

namespace Forensic::UI {
class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget *parent = nullptr);
private:
    void loadSettings();
    void saveSettings();

    // AI
    QLineEdit *m_apiKeyEdit{nullptr};
    QComboBox *m_providerCombo{nullptr};
    QLineEdit *m_modelEdit{nullptr};
    QLineEdit *m_baseUrlEdit{nullptr};
    QSpinBox  *m_maxTokensSpin{nullptr};

    // General
    QLineEdit *m_logPathEdit{nullptr};
    QComboBox *m_logLevelCombo{nullptr};
};
} // namespace Forensic::UI
