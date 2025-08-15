#include <gtest/gtest.h>
#include <sys/syscall.h>

#include <unordered_set>

#include "sandbox/core/logger.h"
#include "sandbox/security/policy.h"

using namespace sandbox::security;

class SecurityPolicyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Initialize logger for tests
    logger_ = std::make_unique<sandbox::core::Logger>("test_policy.log");
  }

  void TearDown() override { logger_.reset(); }

  std::unique_ptr<sandbox::core::Logger> logger_;
};

// Test SecurityPolicy construction and basic properties
TEST_F(SecurityPolicyTest, DefaultConstruction) {
  SecurityPolicy policy;

  EXPECT_EQ(policy.get_level(), PolicyLevel::MODERATE);
  EXPECT_EQ(policy.get_default_action(), SyscallAction::DENY);
  EXPECT_TRUE(policy.get_log_violations());
  EXPECT_TRUE(policy.is_valid());
}

TEST_F(SecurityPolicyTest, ConstructionWithLevel) {
  SecurityPolicy strict_policy(PolicyLevel::STRICT);
  EXPECT_EQ(strict_policy.get_level(), PolicyLevel::STRICT);

  SecurityPolicy permissive_policy(PolicyLevel::PERMISSIVE);
  EXPECT_EQ(permissive_policy.get_level(), PolicyLevel::PERMISSIVE);
}

// Test policy level setting
TEST_F(SecurityPolicyTest, SetPolicyLevel) {
  SecurityPolicy policy;

  policy.set_policy_level(PolicyLevel::STRICT);
  EXPECT_EQ(policy.get_level(), PolicyLevel::STRICT);

  policy.set_policy_level(PolicyLevel::PERMISSIVE);
  EXPECT_EQ(policy.get_level(), PolicyLevel::PERMISSIVE);
}

// Test default action setting
TEST_F(SecurityPolicyTest, SetDefaultAction) {
  SecurityPolicy policy;

  policy.set_default_action(SyscallAction::ALLOW);
  EXPECT_EQ(policy.get_default_action(), SyscallAction::ALLOW);

  policy.set_default_action(SyscallAction::KILL);
  EXPECT_EQ(policy.get_default_action(), SyscallAction::KILL);

  policy.set_default_action(SyscallAction::TRAP);
  EXPECT_EQ(policy.get_default_action(), SyscallAction::TRAP);
}

// Test logging violations setting
TEST_F(SecurityPolicyTest, SetLogViolations) {
  SecurityPolicy policy;

  policy.set_log_violations(false);
  EXPECT_FALSE(policy.get_log_violations());

  policy.set_log_violations(true);
  EXPECT_TRUE(policy.get_log_violations());
}

// Test individual rule management
TEST_F(SecurityPolicyTest, AddRemoveRules) {
  SecurityPolicy policy;

  // Start with empty custom policy
  policy.set_policy_level(PolicyLevel::CUSTOM);
  policy.clear_rules();

  // Add essential syscalls to make policy valid
  policy.add_rule(SYS_exit, SyscallAction::ALLOW, "Process exit");
  policy.add_rule(SYS_exit_group, SyscallAction::ALLOW, "Thread group exit");

  const auto& rules = policy.get_rules();
  EXPECT_EQ(rules.size(), 2);

  // Check specific rules
  bool found_exit = false;
  bool found_exit_group = false;

  for (const auto& rule : rules) {
    if (rule.syscall_nr == SYS_exit) {
      found_exit = true;
      EXPECT_EQ(rule.action, SyscallAction::ALLOW);
      EXPECT_EQ(rule.description, "Process exit");
    } else if (rule.syscall_nr == SYS_exit_group) {
      found_exit_group = true;
      EXPECT_EQ(rule.action, SyscallAction::ALLOW);
    }
  }

  EXPECT_TRUE(found_exit);
  EXPECT_TRUE(found_exit_group);

  // Test rule removal
  policy.remove_rule(SYS_exit);
  EXPECT_EQ(policy.get_rules().size(), 1);

  // Clear all rules
  policy.clear_rules();
  EXPECT_EQ(policy.get_rules().size(), 0);
}

// Test rule replacement
TEST_F(SecurityPolicyTest, RuleReplacement) {
  SecurityPolicy policy;
  policy.set_policy_level(PolicyLevel::CUSTOM);
  policy.clear_rules();

  // Add a rule
  policy.add_rule(SYS_read, SyscallAction::ALLOW, "Read operation");
  EXPECT_EQ(policy.get_rules().size(), 1);

  // Replace with different action
  policy.add_rule(SYS_read, SyscallAction::DENY, "Deny read");
  EXPECT_EQ(policy.get_rules().size(), 1);

  const auto& rules = policy.get_rules();
  EXPECT_EQ(rules[0].action, SyscallAction::DENY);
  EXPECT_EQ(rules[0].description, "Deny read");
}

// Test bulk syscall operations
TEST_F(SecurityPolicyTest, BulkOperations) {
  SecurityPolicy policy;
  policy.set_policy_level(PolicyLevel::CUSTOM);
  policy.clear_rules();

  std::vector<int> io_syscalls = {SYS_read, SYS_write, SYS_open, SYS_close};
  std::vector<int> memory_syscalls = {SYS_mmap, SYS_munmap, SYS_brk};

  policy.allow_syscalls(io_syscalls);
  policy.deny_syscalls(memory_syscalls);

  const auto& rules = policy.get_rules();
  EXPECT_EQ(rules.size(), 7);

  // Check that I/O syscalls are allowed
  for (int syscall : io_syscalls) {
    bool found = false;
    for (const auto& rule : rules) {
      if (rule.syscall_nr == syscall) {
        EXPECT_EQ(rule.action, SyscallAction::ALLOW);
        found = true;
        break;
      }
    }
    EXPECT_TRUE(found) << "Syscall " << syscall << " not found in rules";
  }

  // Check that memory syscalls are denied
  for (int syscall : memory_syscalls) {
    bool found = false;
    for (const auto& rule : rules) {
      if (rule.syscall_nr == syscall) {
        EXPECT_EQ(rule.action, SyscallAction::DENY);
        found = true;
        break;
      }
    }
    EXPECT_TRUE(found) << "Syscall " << syscall << " not found in rules";
  }
}

// Test predefined policy factories
TEST_F(SecurityPolicyTest, StrictPolicy) {
  SecurityPolicy policy = SecurityPolicy::create_strict_policy();

  EXPECT_EQ(policy.get_level(), PolicyLevel::STRICT);
  EXPECT_TRUE(policy.is_valid());

  const auto& rules = policy.get_rules();
  EXPECT_GT(rules.size(), 0);

  // Should have essential syscalls
  bool has_exit = false;
  bool has_read = false;
  bool has_write = false;

  for (const auto& rule : rules) {
    if (rule.syscall_nr == SYS_exit && rule.action == SyscallAction::ALLOW) {
      has_exit = true;
    } else if (rule.syscall_nr == SYS_read &&
               rule.action == SyscallAction::ALLOW) {
      has_read = true;
    } else if (rule.syscall_nr == SYS_write &&
               rule.action == SyscallAction::ALLOW) {
      has_write = true;
    }
  }

  EXPECT_TRUE(has_exit);
  EXPECT_TRUE(has_read);
  EXPECT_TRUE(has_write);
}

TEST_F(SecurityPolicyTest, ModeratePolicy) {
  SecurityPolicy policy = SecurityPolicy::create_moderate_policy();

  EXPECT_EQ(policy.get_level(), PolicyLevel::MODERATE);
  EXPECT_TRUE(policy.is_valid());

  const auto& rules = policy.get_rules();
  EXPECT_GT(rules.size(), 3);  // Should have more than just essential

  // Should have I/O and memory syscalls
  bool has_open = false;
  bool has_mmap = false;

  for (const auto& rule : rules) {
    if (rule.syscall_nr == SYS_open && rule.action == SyscallAction::ALLOW) {
      has_open = true;
    } else if (rule.syscall_nr == SYS_mmap &&
               rule.action == SyscallAction::ALLOW) {
      has_mmap = true;
    }
  }

  EXPECT_TRUE(has_open);
  EXPECT_TRUE(has_mmap);
}

TEST_F(SecurityPolicyTest, PermissivePolicy) {
  SecurityPolicy policy = SecurityPolicy::create_permissive_policy();

  EXPECT_EQ(policy.get_level(), PolicyLevel::PERMISSIVE);
  EXPECT_TRUE(policy.is_valid());

  const auto& rules = policy.get_rules();
  EXPECT_GT(rules.size(), 6);  // Should have the most rules

  // Should have process syscalls
  bool has_getpid = false;

  for (const auto& rule : rules) {
    if (rule.syscall_nr == SYS_getpid && rule.action == SyscallAction::ALLOW) {
      has_getpid = true;
    }
  }

  EXPECT_TRUE(has_getpid);
}

// Test policy validation
TEST_F(SecurityPolicyTest, PolicyValidation) {
  SecurityPolicy policy;
  policy.set_policy_level(PolicyLevel::CUSTOM);
  policy.clear_rules();

  // Invalid policy without essential syscalls
  EXPECT_FALSE(policy.is_valid());

  // Add essential syscalls
  policy.add_rule(SYS_exit, SyscallAction::ALLOW);
  policy.add_rule(SYS_exit_group, SyscallAction::ALLOW);

  EXPECT_TRUE(policy.is_valid());

  // Test with ALLOW default action
  policy.clear_rules();
  policy.set_default_action(SyscallAction::ALLOW);
  EXPECT_TRUE(policy.is_valid());  // Should be valid with ALLOW default
}

// Test syscall name operations
TEST_F(SecurityPolicyTest, SyscallNameOperations) {
  SecurityPolicy policy;
  policy.set_policy_level(PolicyLevel::CUSTOM);
  policy.clear_rules();

  // Add rule by name
  policy.add_rule("read", SyscallAction::ALLOW, "Read by name");
  policy.add_rule("write", SyscallAction::DENY, "Write by name");

  const auto& rules = policy.get_rules();
  EXPECT_EQ(rules.size(), 2);

  bool found_read = false;
  bool found_write = false;

  for (const auto& rule : rules) {
    if (rule.syscall_nr == SYS_read) {
      found_read = true;
      EXPECT_EQ(rule.action, SyscallAction::ALLOW);
    } else if (rule.syscall_nr == SYS_write) {
      found_write = true;
      EXPECT_EQ(rule.action, SyscallAction::DENY);
    }
  }

  EXPECT_TRUE(found_read);
  EXPECT_TRUE(found_write);
}

// Test SyscallRegistry functionality
class SyscallRegistryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    logger_ = std::make_unique<sandbox::core::Logger>("test_registry.log");
  }

  void TearDown() override { logger_.reset(); }

  std::unique_ptr<sandbox::core::Logger> logger_;
};

TEST_F(SyscallRegistryTest, NameToNumber) {
  EXPECT_EQ(SyscallRegistry::get_syscall_number("read"), SYS_read);
  EXPECT_EQ(SyscallRegistry::get_syscall_number("write"), SYS_write);
  EXPECT_EQ(SyscallRegistry::get_syscall_number("exit"), SYS_exit);

  // Test unknown syscall
  EXPECT_EQ(SyscallRegistry::get_syscall_number("nonexistent"), -1);
}

TEST_F(SyscallRegistryTest, NumberToName) {
  EXPECT_EQ(SyscallRegistry::get_syscall_name(SYS_read), "read");
  EXPECT_EQ(SyscallRegistry::get_syscall_name(SYS_write), "write");
  EXPECT_EQ(SyscallRegistry::get_syscall_name(SYS_exit), "exit");

  // Test unknown syscall number
  std::string unknown_name = SyscallRegistry::get_syscall_name(9999);
  EXPECT_TRUE(unknown_name.find("unknown_") == 0);
}

TEST_F(SyscallRegistryTest, ValidSyscall) {
  EXPECT_TRUE(SyscallRegistry::is_valid_syscall(SYS_read));
  EXPECT_TRUE(SyscallRegistry::is_valid_syscall(SYS_write));
  EXPECT_FALSE(SyscallRegistry::is_valid_syscall(9999));
}

// Test SyscallAction enum
TEST_F(SecurityPolicyTest, SyscallActionEnum) {
  // Test that all enum values are distinct
  std::unordered_set<int> values;
  values.insert(static_cast<int>(SyscallAction::ALLOW));
  values.insert(static_cast<int>(SyscallAction::DENY));
  values.insert(static_cast<int>(SyscallAction::KILL));
  values.insert(static_cast<int>(SyscallAction::TRAP));
  values.insert(static_cast<int>(SyscallAction::LOG));

  EXPECT_EQ(values.size(), 5);
}

// Test PolicyLevel enum
TEST_F(SecurityPolicyTest, PolicyLevelEnum) {
  // Test that all enum values are distinct
  std::unordered_set<int> values;
  values.insert(static_cast<int>(PolicyLevel::STRICT));
  values.insert(static_cast<int>(PolicyLevel::MODERATE));
  values.insert(static_cast<int>(PolicyLevel::PERMISSIVE));
  values.insert(static_cast<int>(PolicyLevel::CUSTOM));

  EXPECT_EQ(values.size(), 4);
}
TEST_F(SecurityPolicyTest, SyscallNameOperations) {
  SecurityPolicy policy;
  policy.set_policy_level(PolicyLevel::CUSTOM);
  policy.clear_rules();

  // Add rule by name
  policy.add_rule("read", SyscallAction::ALLOW, "Read by name");
  policy.add_rule("write", SyscallAction::DENY, "Write by name");

  const auto& rules = policy.get_rules();
  EXPECT_EQ(rules.size(), 2);

  bool found_read = false;
  bool found_write = false;

  for (const auto& rule : rules) {
    if (rule.syscall_nr == SYS_read) {
      found_read = true;
      EXPECT_EQ(rule.action, SyscallAction::ALLOW);
    } else if (rule.syscall_nr == SYS_write) {
      found_write = true;
      EXPECT_EQ(rule.action, SyscallAction::DENY);
    }
  }

  EXPECT_TRUE(found_read);
  EXPECT_TRUE(found_write);
}

// Test SyscallRegistry functionality
class SyscallRegistryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    logger_ = std::make_unique<sandbox::core::Logger>("test_registry.log");
  }

  void TearDown() override { logger_.reset(); }

  std::unique_ptr<sandbox::core::Logger> logger_;
};

TEST_F(SyscallRegistryTest, NameToNumber) {
  EXPECT_EQ(SyscallRegistry::get_syscall_number("read"), SYS_read);
  EXPECT_EQ(SyscallRegistry::get_syscall_number("write"), SYS_write);
  EXPECT_EQ(SyscallRegistry::get_syscall_number("exit"), SYS_exit);

  // Test unknown syscall
  EXPECT_EQ(SyscallRegistry::get_syscall_number("nonexistent"), -1);
}

TEST_F(SyscallRegistryTest, NumberToName) {
  EXPECT_EQ(SyscallRegistry::get_syscall_name(SYS_read), "read");
  EXPECT_EQ(SyscallRegistry::get_syscall_name(SYS_write), "write");
  EXPECT_EQ(SyscallRegistry::get_syscall_name(SYS_exit), "exit");

  // Test unknown syscall number
  std::string unknown_name = SyscallRegistry::get_syscall_name(9999);
  EXPECT_TRUE(unknown_name.find("unknown_") == 0);
}

TEST_F(SyscallRegistryTest, ValidSyscall) {
  EXPECT_TRUE(SyscallRegistry::is_valid_syscall(SYS_read));
  EXPECT_TRUE(SyscallRegistry::is_valid_syscall(SYS_write));
  EXPECT_FALSE(SyscallRegistry::is_valid_syscall(9999));
}

// Test SyscallAction enum
TEST_F(SecurityPolicyTest, SyscallActionEnum) {
  // Test that all enum values are distinct
  std::unordered_set<int> values;
  values.insert(static_cast<int>(SyscallAction::ALLOW));
  values.insert(static_cast<int>(SyscallAction::DENY));
  values.insert(static_cast<int>(SyscallAction::KILL));
  values.insert(static_cast<int>(SyscallAction::TRAP));
  values.insert(static_cast<int>(SyscallAction::LOG));

  EXPECT_EQ(values.size(), 5);
}

// Test PolicyLevel enum
TEST_F(SecurityPolicyTest, PolicyLevelEnum) {
  // Test that all enum values are distinct
  std::unordered_set<int> values;
  values.insert(static_cast<int>(PolicyLevel::STRICT));
  values.insert(static_cast<int>(PolicyLevel::MODERATE));
  values.insert(static_cast<int>(PolicyLevel::PERMISSIVE));
  values.insert(static_cast<int>(PolicyLevel::CUSTOM));

  EXPECT_EQ(values.size(), 4);
}
