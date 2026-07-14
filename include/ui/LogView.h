#pragma once
#include <QWidget>

namespace Forensic::UI {

class LogView : public QWidget {
    Q_OBJECT
public:
    explicit LogView(QWidget *parent = nullptr);
};

} // namespace Forensic::UI
