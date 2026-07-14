# ForensicToolkit CMake helper
# Provides utility macros and version info

set(FORENSIC_TOOLKIT_VERSION "1.0.0")
set(FORENSIC_TOOLKIT_VERSION_MAJOR 1)
set(FORENSIC_TOOLKIT_VERSION_MINOR 0)
set(FORENSIC_TOOLKIT_VERSION_PATCH 0)

# Macro: forensic_add_module(TARGET sources...)
# Convenience wrapper for adding a forensic analysis module library.
macro(forensic_add_module TARGET)
    add_library(${TARGET} STATIC ${ARGN})
    target_include_directories(${TARGET} PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/core
        ${CMAKE_SOURCE_DIR}/include/modules
        ${CMAKE_SOURCE_DIR}/include/utils
    )
    target_link_libraries(${TARGET} PUBLIC
        forensic_core
        Qt6::Core
    )
endmacro()

# Macro: forensic_add_test(TARGET source)
# Convenience wrapper for a Qt Test executable.
macro(forensic_add_test TARGET SOURCE)
    qt_add_executable(${TARGET} ${SOURCE})
    target_link_libraries(${TARGET} PRIVATE
        forensic_core
        forensic_modules
        forensic_services
        forensic_utils
        Qt6::Core
        Qt6::Test
        Qt6::Sql
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    target_include_directories(${TARGET} PRIVATE
        ${CMAKE_SOURCE_DIR}/include/core
        ${CMAKE_SOURCE_DIR}/include/modules
        ${CMAKE_SOURCE_DIR}/include/services
        ${CMAKE_SOURCE_DIR}/include/repositories
        ${CMAKE_SOURCE_DIR}/include/utils
    )
    add_test(NAME ${TARGET} COMMAND ${TARGET})
endmacro()

message(STATUS "ForensicToolkit v${FORENSIC_TOOLKIT_VERSION} build system loaded")
