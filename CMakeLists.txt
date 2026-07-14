cmake_minimum_required(VERSION 3.21)
project(ForensicToolkit VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# ─── Build type ───────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# ─── Output directories ───────────────────────────────────────
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ─── Compiler flags ───────────────────────────────────────────
if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8 /MP)
  add_compile_definitions(
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0A00
  )
else()
  add_compile_options(-Wall -Wextra -Wpedantic -pthread)
endif()

# ─── CMake helpers ────────────────────────────────────────────
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# ─── Find Qt6 ─────────────────────────────────────────────────
find_package(Qt6 REQUIRED COMPONENTS
  Core Widgets Gui Network Sql Charts PrintSupport Concurrent Xml
)
# WebEngineWidgets is optional (large dependency)
find_package(Qt6 QUIET COMPONENTS WebEngineWidgets)

# ─── Find OpenSSL ─────────────────────────────────────────────
find_package(OpenSSL REQUIRED)

# ─── SQLite3 – use Qt's SQL plugin (already found via Qt6::Sql)
# Bundled fallback only if system SQLite3 header is needed directly
find_package(SQLite3 QUIET)
if(NOT SQLite3_FOUND)
  # Provide a minimal interface target so code compiles; Qt Sql handles runtime
  add_library(SQLite3_iface INTERFACE)
  add_library(SQLite::SQLite3 ALIAS SQLite3_iface)
endif()

# ─── Global include paths ─────────────────────────────────────
include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/include/core
  ${CMAKE_SOURCE_DIR}/include/modules
  ${CMAKE_SOURCE_DIR}/include/ui
  ${CMAKE_SOURCE_DIR}/include/services
  ${CMAKE_SOURCE_DIR}/include/repositories
  ${CMAKE_SOURCE_DIR}/include/utils
  ${OPENSSL_INCLUDE_DIR}
)

# ─── Sub-libraries ────────────────────────────────────────────
add_subdirectory(src)

# ─── Main executable ──────────────────────────────────────────
qt_add_executable(ForensicToolkit WIN32
  src/main.cpp
  resources/resources.qrc
)

target_link_libraries(ForensicToolkit PRIVATE
  forensic_core
  forensic_modules
  forensic_ui
  forensic_services
  forensic_repositories
  forensic_utils
  Qt6::Core
  Qt6::Widgets
  Qt6::Gui
  Qt6::Network
  Qt6::Sql
  Qt6::Charts
  Qt6::PrintSupport
  Qt6::Concurrent
  Qt6::Xml
  OpenSSL::SSL
  OpenSSL::Crypto
)

if(Qt6WebEngineWidgets_FOUND)
  target_link_libraries(ForensicToolkit PRIVATE Qt6::WebEngineWidgets)
  target_compile_definitions(ForensicToolkit PRIVATE HAS_WEBENGINE)
endif()

set_target_properties(ForensicToolkit PROPERTIES
  OUTPUT_NAME "ForensicToolkit"
  MACOSX_BUNDLE TRUE
)

# ─── Tests ────────────────────────────────────────────────────
option(BUILD_TESTS "Build unit and integration tests" ON)
if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ─── Install rules ────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS ForensicToolkit
  BUNDLE  DESTINATION .
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY resources/
  DESTINATION ${CMAKE_INSTALL_DATADIR}/forensic-toolkit
  PATTERN "*.qrc" EXCLUDE
)

# ─── CPack packaging ──────────────────────────────────────────
set(CPACK_PACKAGE_NAME              "ForensicToolkit")
set(CPACK_PACKAGE_VERSION           "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SHORT "Enterprise Digital Forensics Investigation Toolkit")
set(CPACK_PACKAGE_VENDOR            "ForensicToolkit Project")
if(WIN32)
  set(CPACK_GENERATOR "ZIP;NSIS")
else()
  set(CPACK_GENERATOR "TGZ;DEB")
endif()
include(CPack)
