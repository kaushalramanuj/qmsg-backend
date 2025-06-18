cmake_minimum_required(VERSION 3.10)
project(kyber C)

# Enable position independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set output directory to current directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# Add library
add_library(kyber SHARED kyber.c)

# Windows-specific settings
if(WIN32)
    target_compile_definitions(kyber PRIVATE WIN32_DLL)
    if(MSVC)
        # Disable specific warnings
        target_compile_options(kyber PRIVATE /wd4996)
    endif()
endif()

# Set output name and prefix
set_target_properties(kyber PROPERTIES
    PREFIX ""
    OUTPUT_NAME "kyber"
    WINDOWS_EXPORT_ALL_SYMBOLS ON
) 