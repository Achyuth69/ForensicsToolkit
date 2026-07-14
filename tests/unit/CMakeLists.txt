find_package(Qt6 REQUIRED COMPONENTS Test Sql)

set(UNIT_TESTS
    test_hash
    test_filesystem
    test_integrity
    test_malware
    test_case_service
    test_utils
)

foreach(T IN LISTS UNIT_TESTS)
    qt_add_executable(${T} ${T}.cpp)

    target_link_libraries(${T} PRIVATE
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
    target_include_directories(${T} PRIVATE
        ${CMAKE_SOURCE_DIR}/include/core
        ${CMAKE_SOURCE_DIR}/include/modules
        ${CMAKE_SOURCE_DIR}/include/services
        ${CMAKE_SOURCE_DIR}/include/repositories
        ${CMAKE_SOURCE_DIR}/include/utils
        ${OPENSSL_INCLUDE_DIR}
    )
    add_test(NAME ${T} COMMAND ${T})
    set_tests_properties(${T} PROPERTIES TIMEOUT 60)
endforeach()
