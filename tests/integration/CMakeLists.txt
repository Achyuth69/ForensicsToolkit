find_package(Qt6 REQUIRED COMPONENTS Test Sql)

qt_add_executable(test_integration_case test_integration_case.cpp)

target_link_libraries(test_integration_case PRIVATE
    forensic_core
    forensic_modules
    forensic_services
    forensic_repositories
    forensic_utils
    Qt6::Core
    Qt6::Test
    Qt6::Sql
    OpenSSL::SSL
    OpenSSL::Crypto
)
target_include_directories(test_integration_case PRIVATE
    ${CMAKE_SOURCE_DIR}/include/core
    ${CMAKE_SOURCE_DIR}/include/modules
    ${CMAKE_SOURCE_DIR}/include/services
    ${CMAKE_SOURCE_DIR}/include/repositories
    ${CMAKE_SOURCE_DIR}/include/utils
    ${OPENSSL_INCLUDE_DIR}
)
add_test(NAME test_integration_case COMMAND test_integration_case)
set_tests_properties(test_integration_case PROPERTIES TIMEOUT 120)
