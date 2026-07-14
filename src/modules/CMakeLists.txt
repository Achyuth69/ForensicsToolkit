add_library(forensic_modules STATIC
    case_management/CaseManagement.cpp
    filesystem_analyzer/FileSystemAnalyzer.cpp
    file_integrity/FileIntegrityModule.cpp
    memory_analysis/MemoryAnalyzer.cpp
    network_forensics/NetworkForensics.cpp
    event_log_parser/EventLogParser.cpp
    malware_detection/MalwareDetector.cpp
    ai_assistant/AiAssistant.cpp
    report_generator/ReportGenerator.cpp
    ${CMAKE_SOURCE_DIR}/include/modules/AiAssistant.h
    ${CMAKE_SOURCE_DIR}/include/modules/EventLogParser.h
    ${CMAKE_SOURCE_DIR}/include/modules/FileIntegrityModule.h
    ${CMAKE_SOURCE_DIR}/include/modules/FileSystemAnalyzer.h
    ${CMAKE_SOURCE_DIR}/include/modules/MalwareDetector.h
    ${CMAKE_SOURCE_DIR}/include/modules/MemoryAnalyzer.h
    ${CMAKE_SOURCE_DIR}/include/modules/NetworkForensics.h
    ${CMAKE_SOURCE_DIR}/include/modules/ReportGenerator.h
)
set_target_properties(forensic_modules PROPERTIES AUTOMOC ON)

target_include_directories(forensic_modules PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/modules
    ${CMAKE_SOURCE_DIR}/include/core
    ${CMAKE_SOURCE_DIR}/include/utils
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(forensic_modules PUBLIC
    forensic_core
    forensic_utils
    Qt6::Core
    Qt6::Network
    Qt6::Xml
    Qt6::Sql
    Qt6::PrintSupport
    Qt6::Concurrent
    Qt6::Widgets
    Qt6::Gui
    OpenSSL::SSL
    OpenSSL::Crypto
)
