#pragma once
#include <QWidget>

namespace Forensic::UI {

class FileIntegrityView : public QWidget {
    Q_OBJECT
public:
    explicit FileIntegrityView(QWidget *parent = nullptr);
};

} // namespace Forensic::UI
