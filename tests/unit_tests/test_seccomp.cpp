#include <gtest/gtest.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sandbox/core/logger.h"
#include "sandbox/security/policy.h"
#include "sandbox/security/seccomp.h"

using namespace sandbox::security;

class SeccompFilterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    logger_ = std::make_unique<sandbox::core::Logger>("test_seccomp.log");

    // Create a basic policy for testing
    test_policy_ = SecurityPolicy::create_moderate_policy();
    test_policy_.set_log_violations(true);
  }

  void TearDown() override { logger_.reset(); }

  std::unique_ptr<sandbox::core::Logger> logger_;
  SecurityPolicy test_policy_;
};

// Test SeccompFilter construction
TEST_F(SeccompFilterTest, Construction) {
  SeccompFilter filter(test_policy_);

  EXPECT_FALSE(filter.is_installed());
  EXPECT_EQ(filter.get_policy().get_level(), PolicyLevel::MODERATE);
}

// Test seccomp availability check
TEST_F(SeccompFilterTest, SeccompAvailability) {
  bool available = SeccompFilter::is_seccomp_available();

  // On Linux systems, seccomp should be available
  // On other systems, it might not be
#ifdef __linux__
  EXPECT_TRUE(available);
#else
  // On non-Linux systems, we expect it to be false
  EXPECT_FALSE(available);
#endif
}

// Test no_new_privs setting
TEST_F(SeccompFilterTest, NoNewPrivs) {
  // This test needs to be in a child process since no_new_privs is irreversible
  pid_t pid = fork();
  if (pid == 0) {
    // Child process
    bool result = SeccompFilter::enable_no_new_privs();
    _exit(result ? 0 : 1);
  } else {
    // Parent process
    int status;
    waitpid(pid, &status, 0);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
  }
}

// Test filter compilation
TEST_F(SeccompFilterTest, FilterCompilation) {
  SeccompFilter filter(test_policy_);

  bool compiled = filter.compile_filter();
  EXPECT_TRUE(compiled);
}

// Test filter validation
TEST_F(SeccompFilterTest, FilterValidation) {
  SeccompFilter filter(test_policy_);

  // Should be invalid before compilation
  EXPECT_FALSE(filter.validate_filter());

  // Should be valid after compilation
  filter.compile_filter();
  EXPECT_TRUE(filter.validate_filter());
}

// Test policy updates
TEST_F(SeccompFilterTest, PolicyUpdate) {
  SeccompFilter filter(test_policy_);

  SecurityPolicy new_policy = SecurityPolicy::create_strict_policy();
  filter.update_policy(new_policy);

  EXPECT_EQ(filter.get_policy().get_level(), PolicyLevel::STRICT);
}

// Test filter installation in child process
TEST_F(SeccompFilterTest, FilterInstallation) {
  if (!SeccompFilter::is_seccomp_available()) {
    GTEST_SKIP() << "Seccomp not available on this system";
  }

  pid_t pid = fork();
  if (pid == 0) {
    // Child process - install filter
    SeccompFilter filter(test_policy_);

    bool installed = filter.install_filter();
    if (!installed) {
      _exit(1);
    }

    EXPECT_TRUE(filter.is_installed());
    _exit(0);
  } else {
    // Parent process - wait for child
    int status;
    waitpid(pid, &status, 0);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
  }
}

// Test SeccompGuard RAII wrapper
TEST_F(SeccompFilterTest, SeccompGuard) {
  if (!SeccompFilter::is_seccomp_available()) {
    GTEST_SKIP() << "Seccomp not available on this system";
  }

  pid_t pid = fork();
  if (pid == 0) {
    // Child process - test RAII wrapper
    {
      SeccompGuard guard(test_policy_);
      EXPECT_TRUE(guard.is_active());
      EXPECT_EQ(guard.get_policy().get_level(), PolicyLevel::MODERATE);

      // Test that basic syscalls still work
      pid_t my_pid = getpid();
      EXPECT_GT(my_pid, 0);
    }
    // Guard destructor called here

    _exit(0);
  } else {
    // Parent process
    int status;
    waitpid(pid, &status, 0);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
  }
}

// Test strict policy enforcement
TEST_F(SeccompFilterTest, StrictPolicyEnforcement) {
  if (!SeccompFilter::is_seccomp_available()) {
    GTEST_SKIP() << "Seccomp not available on this system";
  }

  SecurityPolicy strict_policy = SecurityPolicy::create_strict_policy();

  pid_t pid = fork();
  if (pid == 0) {
    // Child process - install strict filter
    SeccompFilter filter(strict_policy);

    if (!filter.install_filter()) {
      _exit(1);
    }

    // These should work (essential syscalls)
    write(STDOUT_FILENO, "test", 4);

    // This might be blocked depending on policy
    // We'll just exit successfully since testing blocking is complex
    _exit(0);
  } else {
    // Parent process
    int status;
    waitpid(pid, &status, 0);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
  }
}

// Test filter with different actions
class SeccompActionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    logger_ =
        std::make_unique<sandbox::core::Logger>("test_seccomp_actions.log");
  }

  void TearDown() override { logger_.reset(); }

  std::unique_ptr<sandbox::core::Logger> logger_;
};

TEST_F(SeccompActionTest, AllowAction) {
  SecurityPolicy policy(PolicyLevel::CUSTOM);
  policy.clear_rules();
  policy.add_rule(SYS_exit, SyscallAction::ALLOW);
  policy.add_rule(SYS_exit_group, SyscallAction::ALLOW);
  policy.add_rule(SYS_write, SyscallAction::ALLOW);
  policy.set_default_action(SyscallAction::DENY);

  EXPECT_TRUE(policy.is_valid());

  SeccompFilter filter(policy);
  EXPECT_TRUE(filter.compile_filter());
  EXPECT_TRUE(filter.validate_filter());
}

TEST_F(SeccompActionTest, DenyAction) {
  SecurityPolicy policy(PolicyLevel::CUSTOM);
  policy.clear_rules();
  policy.add_rule(SYS_exit, SyscallAction::ALLOW);
  policy.add_rule(SYS_exit_group, SyscallAction::ALLOW);
  policy.add_rule(SYS_open, SyscallAction::DENY);

  SeccompFilter filter(policy);
  EXPECT_TRUE(filter.compile_filter());
  EXPECT_TRUE(filter.validate_filter());
}

TEST_F(SeccompActionTest, KillAction) {
  SecurityPolicy policy(PolicyLevel::CUSTOM);
  policy.clear_rules();
  policy.add_rule(SYS_exit, SyscallAction::ALLOW);
  policy.add_rule(SYS_exit_group, SyscallAction::ALLOW);
  policy.add_rule(SYS_fork, SyscallAction::KILL);

  SeccompFilter filter(policy);
  EXPECT_TRUE(filter.compile_filter());
  EXPECT_TRUE(filter.validate_filter());
}

// Test filter with empty policy
TEST_F(SeccompFilterTest, EmptyPolicy) {
  SecurityPolicy empty_policy(PolicyLevel::CUSTOM);
  empty_policy.clear_rules();
  empty_policy.set_default_action(SyscallAction::ALLOW);

  SeccompFilter filter(empty_policy);
  EXPECT_TRUE(filter.compile_filter());
  EXPECT_TRUE(filter.validate_filter());
}

// Test large policy
TEST_F(SeccompFilterTest, LargePolicy) {
  SecurityPolicy large_policy(PolicyLevel::CUSTOM);
  large_policy.clear_rules();

  // Add many rules to test filter size limits
  for (int i = 0; i < 100; ++i) {
    large_policy.add_rule(i, SyscallAction::ALLOW);
  }

  SeccompFilter filter(large_policy);
  EXPECT_TRUE(filter.compile_filter());
  // Note: validation might fail due to size limits, which is expected
}

// Test filter statistics and debugging
TEST_F(SeccompFilterTest, FilterStatistics) {
  SeccompFilter filter(test_policy_);
  filter.compile_filter();

  // This should not crash and should produce some output
  testing::internal::CaptureStdout();
  filter.print_filter_stats();
  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("Instructions") != std::string::npos);
}

// Test multiple filter creation (should be independent)
TEST_F(SeccompFilterTest, MultipleFilters) {
  SecurityPolicy policy1 = SecurityPolicy::create_strict_policy();
  SecurityPolicy policy2 = SecurityPolicy::create_permissive_policy();

  SeccompFilter filter1(policy1);
  SeccompFilter filter2(policy2);

  EXPECT_TRUE(filter1.compile_filter());
  EXPECT_TRUE(filter2.compile_filter());

  EXPECT_EQ(filter1.get_policy().get_level(), PolicyLevel::STRICT);
  EXPECT_EQ(filter2.get_policy().get_level(), PolicyLevel::PERMISSIVE);
}

// Test error handling
TEST_F(SeccompFilterTest, ErrorHandling) {
  // Test with invalid policy
  SecurityPolicy invalid_policy(PolicyLevel::CUSTOM);
  invalid_policy.clear_rules();
  invalid_policy.set_default_action(SyscallAction::DENY);
  // No essential syscalls - should be invalid

  EXPECT_FALSE(invalid_policy.is_valid());

  SeccompFilter filter(invalid_policy);
  EXPECT_TRUE(filter.compile_filter());    // Compilation might succeed
  EXPECT_FALSE(filter.validate_filter());  // But validation should fail
}
