# Example programs for the sandbox

# Basic usage example
add_executable(basic_usage basic_usage.cpp)
target_link_libraries(basic_usage sandbox_core)

# Resource testing example
add_executable(resource_test resource_test.cpp)
target_link_libraries(resource_test sandbox_core)

# Malicious program simulation
add_executable(malicious_sim malicious_sim.cpp)
target_link_libraries(malicious_sim sandbox_core)

# Phase 2: Security policy examples
add_executable(security_demo security_demo.cpp)
target_link_libraries(security_demo sandbox_security sandbox_core)

# Phase 2: Syscall testing programs
add_executable(syscall_test syscall_test.cpp)
target_link_libraries(syscall_test sandbox_core)

# Phase 2: Policy configuration example
add_executable(policy_config policy_config.cpp)
target_link_libraries(policy_config sandbox_security sandbox_core)

# Install examples
install(TARGETS 
    basic_usage 
    resource_test 
    malicious_sim
    security_demo
    syscall_test
    policy_config
    DESTINATION share/sandbox/examples
)

# Install example source files for reference
install(FILES
    basic_usage.cpp
    resource_test.cpp
    malicious_sim.cpp
    security_demo.cpp
    syscall_test.cpp
    policy_config.cpp
    DESTINATION share/sandbox/examples/src
)
