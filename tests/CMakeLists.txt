# Google Test setup
find_package(GTest QUIET)

if(NOT GTest_FOUND)
    message(STATUS "Google Test not found, downloading...")
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50e33f9fade55a85b6f7e4846a9918.zip
    )
    FetchContent_MakeAvailable(googletest)
endif()

# Test source files
set(UNIT_TEST_SOURCES
    unit_tests/test_logger.cpp
    unit_tests/test_config.cpp
    unit_tests/test_sandbox.cpp
    unit_tests/test_security_policy.cpp  # Phase 2
    unit_tests/test_seccomp.cpp          # Phase 2
)

set(INTEGRATION_TEST_SOURCES
    integration_tests/test_integration.cpp
    integration_tests/test_security_integration.cpp  # Phase 2
)

# All test sources combined
set(ALL_TEST_SOURCES
    ${UNIT_TEST_SOURCES}
    ${INTEGRATION_TEST_SOURCES}
    test_main.cpp  # Main test entry point  
)

# Create main test executable with all tests
add_executable(sandbox_tests ${ALL_TEST_SOURCES})

# Link libraries
target_link_libraries(sandbox_tests
    sandbox_security
    sandbox_core
    gtest_main
    gtest
    Threads::Threads
)

# Platform-specific test libraries
if(UNIX AND NOT APPLE AND SECCOMP_LIBRARY)
    target_link_libraries(sandbox_tests ${SECCOMP_LIBRARY})
endif()

# Add tests to CTest
add_test(NAME SandboxAllTests COMMAND sandbox_tests)

# Individual unit test executables for development
add_executable(test_logger unit_tests/test_logger.cpp)
target_link_libraries(test_logger sandbox_core gtest_main)
add_test(NAME LoggerUnitTest COMMAND test_logger)

add_executable(test_config unit_tests/test_config.cpp)
target_link_libraries(test_config sandbox_core gtest_main)
add_test(NAME ConfigUnitTest COMMAND test_config)

add_executable(test_sandbox unit_tests/test_sandbox.cpp)
target_link_libraries(test_sandbox sandbox_security sandbox_core gtest_main)
add_test(NAME SandboxUnitTest COMMAND test_sandbox)

# Phase 2 security unit tests
if(SECCOMP_AVAILABLE)
    add_executable(test_security_policy unit_tests/test_security_policy.cpp)
    target_link_libraries(test_security_policy sandbox_security sandbox_core gtest_main)
    add_test(NAME SecurityPolicyUnitTest COMMAND test_security_policy)
    
    add_executable(test_seccomp unit_tests/test_seccomp.cpp)
    target_link_libraries(test_seccomp sandbox_security sandbox_core gtest_main)
    add_test(NAME SeccompUnitTest COMMAND test_seccomp)
    
    # Combined security tests
    add_executable(test_security_combined 
        unit_tests/test_security_policy.cpp 
        unit_tests/test_seccomp.cpp
    )
    target_link_libraries(test_security_combined sandbox_security sandbox_core gtest_main)
    add_test(NAME SecurityCombinedTest COMMAND test_security_combined)
endif()

# Integration test executables
add_executable(test_integration integration_tests/test_integration.cpp)
target_link_libraries(test_integration sandbox_security sandbox_core gtest_main)
add_test(NAME IntegrationTest COMMAND test_integration)

if(SECCOMP_AVAILABLE)
    add_executable(test_security_integration integration_tests/test_security_integration.cpp)
    target_link_libraries(test_security_integration sandbox_security sandbox_core gtest_main)
    add_test(NAME SecurityIntegrationTest COMMAND test_security_integration)
endif()

# Test installation
install(TARGETS sandbox_tests DESTINATION share/sandbox/tests)

# Install individual test executables for debugging
install(TARGETS 
    test_logger 
    test_config 
    test_sandbox
    test_integration
    DESTINATION share/sandbox/tests/bin
)

# Install security test executables if available
if(SECCOMP_AVAILABLE)
    install(TARGETS 
        test_security_policy
        test_seccomp
        test_security_combined
        test_security_integration
        DESTINATION share/sandbox/tests/bin
    )
endif()

# Test configuration summary
message(STATUS "")
message(STATUS "=== Test Configuration ===")
message(STATUS "Unit tests: ${UNIT_TEST_SOURCES}")
message(STATUS "Integration tests: ${INTEGRATION_TEST_SOURCES}")
message(STATUS "Security tests available: ${SECCOMP_AVAILABLE}")
message(STATUS "Total test files: ${ALL_TEST_SOURCES}")
message(STATUS "==========================")
