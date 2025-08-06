# Tests CMakeLists.txt

include(FetchContent)

# Fetch Google Test
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0  # Use a stable release
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Fetch and make available
FetchContent_MakeAvailable(googletest)

# Include Google Test headers
include_directories(${googletest_SOURCE_DIR}/googletest/include)
include_directories(${googletest_SOURCE_DIR}/googlemock/include)# Unit tests

add_executable(unit_tests
    unit_tests/test_logger.cpp
    unit_tests/test_config.cpp
    unit_tests/test_sandbox.cpp
    unit_tests/test_main.cpp
)

# Link against Google Test target_link_libraries
message(STATUS "Google Test libraries: ${GTEST_LIBRARIES}, ${GMOCK_LIBRARIES}")
target_link_libraries(unit_tests
    cpp-sandbox_static
    GTest::gmock_main
    GTest::gtest_main
    Threads::Threads
)

# Integration tests
# add_executable(integration_tests
#     integration_tests/test_resource_limits.cpp
#     integration_tests/test_execution_flow.cpp
#     integration_tests/test_error_handling.cpp
#     integration_tests/integration_test_main.cpp
# )

# target_link_libraries(integration_tests
#    cpp-sandbox_static
#     GTest::gmock_main
#     GTest::gtest_main
#     Threads::Threads
# )
#
# Add tests to CTest
add_test(NAME UnitTests COMMAND unit_tests)
add_test(NAME IntegrationTests COMMAND integration_tests)

# Custom target for running all tests
add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --verbose
    DEPENDS unit_tests integration_tests
)
