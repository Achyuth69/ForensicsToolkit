#include "NewCaseDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QDialogButtonBox>
#include <QDateTime>

namespace Forensic::UI {

NewCaseDialog::NewCaseDialog(
    std::shared_ptr<Forensic::Services::CaseService> svc,
    QWidget *parent)
    : QDialog(parent), m_svc(svc)
{
    setWindowTitle("Create New Forensic Case");
    setMinimumWidth(480);
    setModal(true);

    auto *layout = new QVBoxLayout(this);

    auto *titleLabel = new QLabel("New Forensic Case", this);
    titleLabel->setStyleSheet("font-size:16px;font-weight:bold;color:#89b4fa;");
    layout->addWidget(titleLabel);

    auto *form = new QFormLayout();
    m_titleEdit  = new QLineEdit(this);
    m_titleEdit->setPlaceholderText("e.g. Corporate Data Breach Investigation");
    m_numberEdit = new QLineEdit(this);
    m_numberEdit->setPlaceholderText(
        "e.g. FT-" + QDateTime::currentDateTime().toString("yyyyMMdd") + "-001");
    m_descEdit = new QTextEdit(this);
    m_descEdit->setFixedHeight(100);
    m_descEdit->setPlaceholderText("Brief description of the case...");

    form->addRow("Case Title *:", m_titleEdit);
    form->addRow("Case Number *:", m_numberEdit);
    form->addRow("Description:", m_descEdit);
    layout->addLayout(form);

    auto *buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText("Create Case");
    buttons->button(QDialogButtonBox::Ok)->setProperty("primary", true);

    connect(buttons, &QDialogButtonBox::accepted, this, [this]{
        if (m_titleEdit->text().trimmed().isEmpty() ||
            m_numberEdit->text().trimmed().isEmpty()) {
            QMessageBox::warning(this,"Required Fields",
                "Case title and case number are required.");
            return;
        }
        m_svc->createCase(m_titleEdit->text().trimmed(),
                          m_numberEdit->text().trimmed(),
                          m_descEdit->toPlainText().trimmed());
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}

} // namespace Forensic::UI
