#pragma once
#include <QWidget>

namespace Forensic::UI {

class EventLogView : public QWidget {
    Q_OBJECT
public:
    explicit EventLogView(QWidget *parent = nullptr);
};

} // namespace Forensic::UI
