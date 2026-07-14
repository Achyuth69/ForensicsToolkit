add_library(forensic_repositories STATIC
    CaseRepository.cpp
    ${CMAKE_SOURCE_DIR}/include/repositories/CaseRepository.h
)
set_target_properties(forensic_repositories PROPERTIES AUTOMOC ON)

target_include_directories(forensic_repositories PUBLIC
    ${CMAKE_SOURCE_DIR}/include/repositories
    ${CMAKE_SOURCE_DIR}/include/core
)

target_link_libraries(forensic_repositories PUBLIC
    forensic_core
    Qt6::Core
    Qt6::Sql
)
