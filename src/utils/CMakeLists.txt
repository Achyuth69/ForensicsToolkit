add_library(forensic_utils STATIC
    ForensicUtils.cpp
    ${CMAKE_SOURCE_DIR}/include/utils/ForensicUtils.h
)
set_target_properties(forensic_utils PROPERTIES AUTOMOC ON)
target_include_directories(forensic_utils PUBLIC
    ${CMAKE_SOURCE_DIR}/include/utils
)
target_link_libraries(forensic_utils PUBLIC Qt6::Core)
