add_library(forensic_ui STATIC
    views/MainWindow.cpp
    views/DashboardView.cpp
    views/CaseManagerView.cpp
    views/FileSystemView.cpp
    views/FileIntegrityView.cpp
    views/MemoryAnalysisView.cpp
    views/NetworkForensicsView.cpp
    views/EventLogView.cpp
    views/MalwareView.cpp
    views/AiAssistantView.cpp
    views/ReportView.cpp
    views/LogView.cpp
    dialogs/NewCaseDialog.cpp
    dialogs/AddEvidenceDialog.cpp
    dialogs/AddInvestigatorDialog.cpp
    dialogs/SettingsDialog.cpp
    widgets/StatusCard.cpp
    widgets/ScanProgressWidget.cpp
    ${CMAKE_SOURCE_DIR}/include/ui/MainWindow.h
    ${CMAKE_SOURCE_DIR}/include/ui/DashboardView.h
    ${CMAKE_SOURCE_DIR}/include/ui/CaseManagerView.h
    ${CMAKE_SOURCE_DIR}/include/ui/FileSystemView.h
    ${CMAKE_SOURCE_DIR}/include/ui/FileIntegrityView.h
    ${CMAKE_SOURCE_DIR}/include/ui/MemoryAnalysisView.h
    ${CMAKE_SOURCE_DIR}/include/ui/NetworkForensicsView.h
    ${CMAKE_SOURCE_DIR}/include/ui/EventLogView.h
    ${CMAKE_SOURCE_DIR}/include/ui/MalwareView.h
    ${CMAKE_SOURCE_DIR}/include/ui/AiAssistantView.h
    ${CMAKE_SOURCE_DIR}/include/ui/ReportView.h
    ${CMAKE_SOURCE_DIR}/include/ui/LogView.h
    ${CMAKE_SOURCE_DIR}/include/ui/NewCaseDialog.h
    ${CMAKE_SOURCE_DIR}/include/ui/AddEvidenceDialog.h
    ${CMAKE_SOURCE_DIR}/include/ui/AddInvestigatorDialog.h
    ${CMAKE_SOURCE_DIR}/include/ui/SettingsDialog.h
)
set_target_properties(forensic_ui PROPERTIES AUTOMOC ON)

target_include_directories(forensic_ui PUBLIC
    ${CMAKE_SOURCE_DIR}/include/ui
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/core
    ${CMAKE_SOURCE_DIR}/include/modules
    ${CMAKE_SOURCE_DIR}/include/services
    ${CMAKE_SOURCE_DIR}/include/repositories
    ${CMAKE_SOURCE_DIR}/include/utils
)

target_link_libraries(forensic_ui PUBLIC
    forensic_modules
    forensic_services
    forensic_repositories
    forensic_utils
    forensic_core
    Qt6::Core
    Qt6::Widgets
    Qt6::Gui
    Qt6::Charts
    Qt6::PrintSupport
    Qt6::Concurrent
    Qt6::Network
    Qt6::Xml
    Qt6::Sql
)
