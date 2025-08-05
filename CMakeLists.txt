cmake_minimum_required(VERSION 3.16)
project(cpp-sandbox VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find required packages
# find_package(PkgConfig REQUIRED)
# pkg_check_modules(SECCOMP REQUIRED libseccomp)
find_package(Threads REQUIRED)

# Include directories
include_directories(source/src)
include_directories(source/include)
# include_directories(${seccomp_include_dirs})
#
# Source files
#
#
set(SANDBOX_LIB_SOURCES
    source/src/core/sandbox.cpp
    source/src/config/config.cpp
    source/src/core/logger.cpp
)
set(SANDBOX_SOURCES
  ${SANDBOX_LIB_SOURCES}
    source/main.cpp
)

# Create executable
add_executable(${PROJECT_NAME} ${SANDBOX_SOURCES})
add_library(${PROJECT_NAME}_static STATIC ${SANDBOX_LIB_SOURCES})

# Link libraries
target_link_libraries(${PROJECT_NAME} 
    # ${SECCOMP_LIBRARIES}
    Threads::Threads 
)

# Compiler flags
target_compile_options(${PROJECT_NAME} PRIVATE ${SECCOMP_CFLAGS_OTHER})

# # Enable debug symbols for development
# set(CMAKE_BUILD_TYPE Debug)
# target_compile_options(${PROJECT_NAME} PRIVATE -g -Wall -Wextra)
#
# # Add test subdirectory
# add_subdirectory(tests)
#
# # Install target
# install(TARGETS sandbox DESTINATION bin)
#

add_subdirectory(tests)
