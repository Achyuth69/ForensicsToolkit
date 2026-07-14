#include "AddInvestigatorDialog.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QLabel>
#include <QMessageBox>

namespace Forensic::UI {

AddInvestigatorDialog::AddInvestigatorDialog(
    std::shared_ptr<Forensic::Services::CaseService> svc,
    const QString &caseId, QWidget *parent)
    : QDialog(parent), m_svc(svc), m_caseId(caseId)
{
    setWindowTitle("Add Investigator");
    setMinimumWidth(420);
    setModal(true);

    auto *layout = new QVBoxLayout(this);
    auto *title  = new QLabel("Add Investigator to Case", this);
    title->setStyleSheet("font-size:15px;font-weight:bold;color:#89b4fa;");
    layout->addWidget(title);

    auto *form = new QFormLayout();
    m_nameEdit  = new QLineEdit(this); m_nameEdit->setPlaceholderText("Full name");
    m_emailEdit = new QLineEdit(this); m_emailEdit->setPlaceholderText("email@agency.gov");
    m_badgeEdit = new QLineEdit(this); m_badgeEdit->setPlaceholderText("Badge / ID number");
    m_roleEdit  = new QLineEdit(this); m_roleEdit->setPlaceholderText("e.g. Lead Investigator");

    form->addRow("Name *:",  m_nameEdit);
    form->addRow("Email:",   m_emailEdit);
    form->addRow("Badge:",   m_badgeEdit);
    form->addRow("Role:",    m_roleEdit);
    layout->addLayout(form);

    auto *buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText("Add Investigator");
    buttons->button(QDialogButtonBox::Ok)->setProperty("primary", true);

    connect(buttons, &QDialogButtonBox::accepted, this, [this]{
        if (m_nameEdit->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, "Required", "Investigator name is required.");
            return;
        }
        Forensic::Core::Investigator inv;
        inv.name  = m_nameEdit->text().trimmed();
        inv.email = m_emailEdit->text().trimmed();
        inv.badge = m_badgeEdit->text().trimmed();
        inv.role  = m_roleEdit->text().trimmed();
        m_svc->addInvestigator(m_caseId, inv);
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}

} // namespace Forensic::UI
