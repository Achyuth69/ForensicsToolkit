#include "AddEvidenceDialog.h"
#include "HashEngine.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QFileInfo>
#include <QMessageBox>
#include <QProgressDialog>
#include <QLabel>
#include <QLineEdit>

namespace Forensic::UI {

AddEvidenceDialog::AddEvidenceDialog(
    std::shared_ptr<Forensic::Services::CaseService> svc,
    const QString &caseId, QWidget *parent)
    : QDialog(parent), m_svc(svc), m_caseId(caseId)
{
    setWindowTitle("Add Evidence Item");
    setMinimumWidth(520);
    setModal(true);

    auto *layout = new QVBoxLayout(this);
    auto *title  = new QLabel("Add Evidence to Case", this);
    title->setStyleSheet("font-size:15px;font-weight:bold;color:#89b4fa;");
    layout->addWidget(title);

    auto *form = new QFormLayout();

    m_labelEdit = new QLineEdit(this);
    m_labelEdit->setPlaceholderText("e.g. Suspect Laptop Disk Image");

    // File path with browse
    auto *pathRow = new QHBoxLayout();
    m_pathEdit = new QLineEdit(this);
    m_pathEdit->setPlaceholderText("Path to evidence file...");
    auto *browseBtn = new QPushButton("Browse...", this);
    connect(browseBtn, &QPushButton::clicked, this, [this]{
        QString f = QFileDialog::getOpenFileName(this,"Select Evidence File");
        if (!f.isEmpty()) {
            m_pathEdit->setText(f);
            if (m_labelEdit->text().isEmpty())
                m_labelEdit->setText(QFileInfo(f).fileName());
        }
    });
    pathRow->addWidget(m_pathEdit,1);
    pathRow->addWidget(browseBtn);

    m_typeCombo = new QComboBox(this);
    m_typeCombo->addItems({"disk_image","memory_dump","pcap","evtx","file","directory","other"});

    m_acquiredByEdit = new QLineEdit(this);
    m_acquiredByEdit->setPlaceholderText("Investigator name");

    m_custodyEdit = new QLineEdit(this);
    m_custodyEdit->setPlaceholderText("Chain of custody notes...");

    form->addRow("Label *:", m_labelEdit);
    form->addRow("File:", pathRow);
    form->addRow("Type:", m_typeCombo);
    form->addRow("Acquired By:", m_acquiredByEdit);
    form->addRow("Chain of Custody:", m_custodyEdit);
    layout->addLayout(form);

    auto *buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText("Add Evidence");
    buttons->button(QDialogButtonBox::Ok)->setProperty("primary",true);

    connect(buttons, &QDialogButtonBox::accepted, this, [this]{
        if (m_labelEdit->text().trimmed().isEmpty()) {
            QMessageBox::warning(this,"Required","Label is required.");
            return;
        }
        Forensic::Core::EvidenceItem item;
        item.label          = m_labelEdit->text().trimmed();
        item.filePath       = m_pathEdit->text().trimmed();
        item.type           = m_typeCombo->currentText();
        item.acquiredBy     = m_acquiredByEdit->text().trimmed();
        item.chainOfCustody = m_custodyEdit->text().trimmed();

        // Compute hash if file exists
        if (!item.filePath.isEmpty() && QFile::exists(item.filePath)) {
            QFileInfo fi(item.filePath);
            item.sizeBytes = fi.size();
            // For large files show progress
            if (fi.size() < 256 * 1024 * 1024) {
                item.hash = Forensic::Core::HashEngine::computeSHA256(item.filePath);
            }
        }

        m_svc->addEvidence(m_caseId, item);
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}

} // namespace Forensic::UI
