#pragma once
#include <QDialog>
#include <QLineEdit>
#include <memory>
#include "CaseService.h"

namespace Forensic::UI {
class AddInvestigatorDialog : public QDialog {
    Q_OBJECT
public:
    explicit AddInvestigatorDialog(
        std::shared_ptr<Forensic::Services::CaseService> svc,
        const QString &caseId, QWidget *parent = nullptr);
private:
    QLineEdit *m_nameEdit{nullptr};
    QLineEdit *m_emailEdit{nullptr};
    QLineEdit *m_badgeEdit{nullptr};
    QLineEdit *m_roleEdit{nullptr};
    std::shared_ptr<Forensic::Services::CaseService> m_svc;
    QString m_caseId;
};
} // namespace Forensic::UI
