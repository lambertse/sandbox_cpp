cmake_minimum_required(VERSION 3.16)
project(sandbox_cpp VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific options
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    message(STATUS "Using Clang or GCC compiler")
    add_compile_options(-Wall -Wextra -Wpedantic)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    message(STATUS "Using MSVC compiler")
    add_compile_options(/W4)
endif()

# Find required packages
find_package(Threads REQUIRED)

# Check for seccomp availability (Linux only)
if(UNIX AND NOT APPLE)
    include(CheckIncludeFile)
    check_include_file("linux/seccomp.h" HAVE_SECCOMP_H)
    check_include_file("linux/filter.h" HAVE_FILTER_H)
    
    if(HAVE_SECCOMP_H AND HAVE_FILTER_H)
        set(SECCOMP_AVAILABLE TRUE)
        message(STATUS "Seccomp support: Available")
        add_definitions(-DHAVE_SECCOMP=1)
    else()
        set(SECCOMP_AVAILABLE FALSE)
        message(WARNING "Seccomp support: Not available - some features will be disabled")
        add_definitions(-DHAVE_SECCOMP=0)
    endif()
else()
    set(SECCOMP_AVAILABLE FALSE)
    message(WARNING "Seccomp support: Not available on this platform")
    add_definitions(-DHAVE_SECCOMP=0)
endif()

# Include directories
include_directories(source/include)

# Core library source files
set(CORE_SOURCES
    source/src/core/sandbox.cpp
    source/src/core/logger.cpp
    source/src/config/config.cpp
)

# Security library source files (Phase 2)
set(SECURITY_SOURCES
    source/src/security/policy.cpp
    source/src/security/seccomp.cpp
)

# Create core library
add_library(sandbox_core STATIC ${CORE_SOURCES})
target_link_libraries(sandbox_core Threads::Threads)

# Create security library (Phase 2)
add_library(sandbox_security STATIC ${SECURITY_SOURCES})
target_link_libraries(sandbox_security sandbox_core)

# Create main executable
add_executable(sandbox source/main.cpp)
target_link_libraries(sandbox 
    sandbox_security 
    sandbox_core 
    Threads::Threads
)

# Platform-specific libraries
if(UNIX AND NOT APPLE)
    # Link against libseccomp if available
    find_library(SECCOMP_LIBRARY seccomp)
    if(SECCOMP_LIBRARY)
        message(STATUS "Found libseccomp: ${SECCOMP_LIBRARY}")
        target_link_libraries(sandbox_security ${SECCOMP_LIBRARY})
        add_definitions(-DHAVE_LIBSECCOMP=1)
    else()
        message(STATUS "libseccomp not found, using raw syscalls")
        add_definitions(-DHAVE_LIBSECCOMP=0)
    endif()
endif()

# Example programs
# add_subdirectory(examples)

# Tests
option(BUILD_TESTS "Build test programs" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()


# # Documentation
# option(BUILD_DOCS "Build documentation" OFF)
# if(BUILD_DOCS)
#     find_package(Doxygen)
#     if(DOXYGEN_FOUND)
#         configure_file(${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in 
#                       ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
#         add_custom_target(docs
#             ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
#             WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
#             COMMENT "Generating API documentation with Doxygen" VERBATIM
#         )
#     endif()
# endif()

# Package configuration
# set(CPACK_PACKAGE_NAME "sandbox-cpp")
# set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
# set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Secure C++ Program Execution Sandbox")
# set(CPACK_PACKAGE_VENDOR "Sandbox Project")
# set(CPACK_GENERATOR "TGZ;DEB")
# include(CPack)

# Print configuration summary
message(STATUS "")
message(STATUS "=== Sandbox C++ Configuration Summary ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Seccomp available: ${SECCOMP_AVAILABLE}")
if(SECCOMP_LIBRARY)
    message(STATUS "libseccomp: ${SECCOMP_LIBRARY}")
else()
    message(STATUS "libseccomp: Using raw syscalls")
endif()
message(STATUS "Build tests: ${BUILD_TESTS}")
message(STATUS "Build docs: ${BUILD_DOCS}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "==========================================")
message(STATUS "")
