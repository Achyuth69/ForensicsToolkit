#pragma once
#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <memory>
#include "CaseService.h"

namespace Forensic::UI {
class AddEvidenceDialog : public QDialog {
    Q_OBJECT
public:
    explicit AddEvidenceDialog(std::shared_ptr<Forensic::Services::CaseService> svc,
                               const QString &caseId, QWidget *parent = nullptr);
private:
    QLineEdit *m_labelEdit{nullptr};
    QLineEdit *m_pathEdit{nullptr};
    QComboBox *m_typeCombo{nullptr};
    QLineEdit *m_acquiredByEdit{nullptr};
    QLineEdit *m_custodyEdit{nullptr};
    std::shared_ptr<Forensic::Services::CaseService> m_svc;
    QString m_caseId;
};
} // namespace Forensic::UI
