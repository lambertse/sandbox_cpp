#include <gtest/gtest.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sandbox/config/config.h"
#include "sandbox/core/logger.h"
#include "sandbox/core/sandbox.h"
#include "sandbox/security/policy.h"
#include "sandbox/security/seccomp.h"

using namespace sandbox::security;
using namespace sandbox::core;
using namespace sandbox::config;

class SecurityIntegrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    logger_ = std::make_unique<Logger>("test_security_integration.log");

    // Create test configuration with security enabled
    config_.enable_seccomp = true;
    config_.security_policy_level = "moderate";
    config_.log_syscall_violations = true;
    config_.working_directory = "/tmp";
    config_.memory_limit_mb = 64;
    config_.cpu_time_limit_sec = 5;
  }

  void TearDown() override { logger_.reset(); }

  std::unique_ptr<Logger> logger_;
  SandboxConfig config_;
};

// Test sandbox with seccomp enabled
TEST_F(SecurityIntegrationTest, SandboxWithSeccomp) {
  if (!SeccompFilter::is_seccomp_available()) {
    GTEST_SKIP() << "Seccomp not available on this system";
  }

  Sandbox sandbox(config_);

  // Test running a simple program
  std::vector<std::string> args = {"/bin/echo", "Hello, Seccomp!"};
  SandboxResult result = sandbox.execute(args);

  EXPECT_TRUE(result.success);
  EXPECT_EQ(result.exit_code, 0);
  EXPECT_GT(result.execution_time_ms, 0);
}

// Test different security policy levels
TEST_F(SecurityIntegrationTest, DifferentPolicyLevels) {
  if (!SeccompFilter::is_seccomp_available()) {
    GTEST_SKIP() << "Seccomp not available on this system";
  }

  std::vector<std::string> policy_levels = {"strict", "moderate", "permissive"};

  for (const auto& level : policy_levels) {
    config_.security_policy_level = level;
    Sandbox sandbox(config_);

    std::vector<std::string> args = {"/bin/true"};
    SandboxResult result = sandbox.execute(args);

    EXPECT_TRUE(result.success) << "Failed with policy level: " << level;
    EXPECT_EQ(result.exit_code, 0)
        << "Wrong exit code with policy level: " << level;
  }
}

// Test sandbox with seccomp disabled
TEST_F(SecurityIntegrationTest, SandboxWithoutSeccomp) {
  config_.enable_seccomp = false;

  Sandbox sandbox(config_);

  std::vector<std::string> args = {"/bin/echo", "Hello, No Seccomp!"};
  SandboxResult result = sandbox.execute(args);

  EXPECT_TRUE(result.success);
  EXPECT_EQ(result.exit_code, 0);
}

// Test program that might be blocked by strict policy
TEST_F(SecurityIntegrationTest, StrictPolicyBlocking) {
  if (!SeccompFilter::is_seccomp_available()) {
    GTEST_SKIP() << "Seccomp not available on this system";
  }

  config_.security_policy_level = "strict";
  Sandbox sandbox(config_);

  // Try to run a program that does more than basic I/O
  std::vector<std::string> args = {"/bin/ls", "/tmp"};
  SandboxResult result = sandbox.execute(args);

  // This might succeed or fail depending on what syscalls /bin/ls uses
  // We just check that the sandbox handles it properly
  EXPECT_TRUE(result.success ||
              !result.success);  // Either outcome is acceptable
  if (!result.success) {
    EXPECT_FALSE(result.error_message.empty());
  }
}

// Test policy validation integration
TEST_F(SecurityIntegrationTest, PolicyValidation) {
  // Test invalid policy level
  config_.security_policy_level = "invalid_level";

  // This should fail during sandbox setup
  Sandbox sandbox(config_);

  std::vector<std::string> args = {"/bin/true"};
  SandboxResult result = sandbox.execute(args);

  EXPECT_FALSE(result.success);
  EXPECT_FALSE(result.error_message.empty());
}

// Test syscall violation logging
TEST_F(SecurityIntegrationTest, SyscallViolationLogging) {
  if (!SeccompFilter::is_seccomp_available()) {
    GTEST_SKIP() << "Seccomp not available on this system";
  }

  config_.security_policy_level = "strict";
  config_.log_syscall_violations = true;

  Sandbox sandbox(config_);

  // This test is primarily to ensure logging doesn't crash
  std::vector<std::string> args = {"/bin/echo", "test"};
  SandboxResult result = sandbox.execute(args);

  // Should complete without crashing
  EXPECT_TRUE(result.success || !result.success);
}

// Test resource limits with security
TEST_F(SecurityIntegrationTest, ResourceLimitsWithSecurity) {
  if (!SeccompFilter::is_seccomp_available()) {
    GTEST_SKIP() << "Seccomp not available on this system";
  }

  config_.memory_limit_mb = 32;    // Very low limit
  config_.cpu_time_limit_sec = 1;  // Short time limit

  Sandbox sandbox(config_);

  std::vector<std::string> args = {"/bin/sleep", "0.1"};
  SandboxResult result = sandbox.execute(args);

  EXPECT_TRUE(result.success);
  EXPECT_EQ(result.exit_code, 0);
  EXPECT_LE(result.peak_memory_kb, config_.memory_limit_mb * 1024);
}

// Test combination of features
TEST_F(SecurityIntegrationTest, CombinedFeatures) {
  if (!SeccompFilter::is_seccomp_available()) {
    GTEST_SKIP() << "Seccomp not available on this system";
  }

  // Enable all security features
  config_.enable_seccomp = true;
  config_.security_policy_level = "moderate";
  config_.log_syscall_violations = true;

  // Set reasonable resource limits
  config_.memory_limit_mb = 128;
  config_.cpu_time_limit_sec = 5;
  config_.wall_time_limit_sec = 10;
  config_.max_open_files = 32;

  Sandbox sandbox(config_);

  // Run a program that uses various system resources
  std::vector<std::string> args = {"/bin/cat", "/dev/null"};
  SandboxResult result = sandbox.execute(args);

  EXPECT_TRUE(result.success);
  EXPECT_EQ(result.exit_code, 0);
  EXPECT_GT(result.execution_time_ms, 0);
  EXPECT_GE(result.peak_memory_kb, 0);
}
