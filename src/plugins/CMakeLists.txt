# Plugins are optional shared libraries loaded at runtime.
# Each plugin target is built as a MODULE (shared library).

option(BUILD_SAMPLE_PLUGIN "Build the sample hash analyzer plugin" OFF)

if(BUILD_SAMPLE_PLUGIN)
    add_library(plugin_hash_analyzer MODULE
        HashAnalyzerPlugin.cpp
    )
    target_include_directories(plugin_hash_analyzer PRIVATE
        ${CMAKE_SOURCE_DIR}/include/core
    )
    target_link_libraries(plugin_hash_analyzer PRIVATE
        forensic_core
        Qt6::Core
    )
    set_target_properties(plugin_hash_analyzer PROPERTIES
        PREFIX ""
        OUTPUT_NAME "HashAnalyzerPlugin"
    )
endif()
