#pragma once
#include <QDialog>
#include <QLineEdit>
#include <QTextEdit>
#include <memory>
#include "CaseService.h"

namespace Forensic::UI {
class NewCaseDialog : public QDialog {
    Q_OBJECT
public:
    explicit NewCaseDialog(std::shared_ptr<Forensic::Services::CaseService> svc,
                           QWidget *parent = nullptr);
private:
    QLineEdit *m_titleEdit{nullptr};
    QLineEdit *m_numberEdit{nullptr};
    QTextEdit *m_descEdit{nullptr};
    std::shared_ptr<Forensic::Services::CaseService> m_svc;
};
} // namespace Forensic::UI
