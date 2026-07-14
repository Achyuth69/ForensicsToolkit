add_library(forensic_core STATIC
    ForensicCase.cpp
    Logger.cpp
    HashEngine.cpp
    ThreadPool.cpp
    ${CMAKE_SOURCE_DIR}/include/core/Logger.h
    ${CMAKE_SOURCE_DIR}/include/core/ForensicCase.h
    ${CMAKE_SOURCE_DIR}/include/core/HashEngine.h
    ${CMAKE_SOURCE_DIR}/include/core/ThreadPool.h
)

set_target_properties(forensic_core PROPERTIES AUTOMOC ON)

target_include_directories(forensic_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include/core
    ${CMAKE_SOURCE_DIR}/include/utils
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(forensic_core PUBLIC
    Qt6::Core
    Qt6::Sql
    OpenSSL::SSL
    OpenSSL::Crypto
)
