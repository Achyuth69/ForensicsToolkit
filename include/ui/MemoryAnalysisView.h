#pragma once
#include <QWidget>

namespace Forensic::UI {

class MemoryAnalysisView : public QWidget {
    Q_OBJECT
public:
    explicit MemoryAnalysisView(QWidget *parent = nullptr);
};

} // namespace Forensic::UI
