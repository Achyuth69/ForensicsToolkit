add_library(forensic_services STATIC
    CaseService.cpp
    ${CMAKE_SOURCE_DIR}/include/services/CaseService.h
)
set_target_properties(forensic_services PROPERTIES AUTOMOC ON)

target_include_directories(forensic_services PUBLIC
    ${CMAKE_SOURCE_DIR}/include/services
    ${CMAKE_SOURCE_DIR}/include/repositories
    ${CMAKE_SOURCE_DIR}/include/core
)

target_link_libraries(forensic_services PUBLIC
    forensic_repositories
    forensic_core
    Qt6::Core
    Qt6::Sql
)
