#include <sys/syscall.h>

#include <algorithm>
#include <unordered_map>

#include "sandbox/core/logger.h"
#include "sandbox/security/policy.h"

namespace sandbox {
namespace security {

// Static member initialization
std::unordered_map<std::string, int> SyscallRegistry::name_to_number_;
std::unordered_map<int, std::string> SyscallRegistry::number_to_name_;
bool SyscallRegistry::initialized_ = false;

SecurityPolicy::SecurityPolicy(PolicyLevel level)
    : level_(level),
      default_action_(SyscallAction::DENY),
      log_violations_(true) {
  load_predefined_policy(level);
}

void SecurityPolicy::set_policy_level(PolicyLevel level) {
  level_ = level;
  clear_rules();
  load_predefined_policy(level);
}

void SecurityPolicy::set_default_action(SyscallAction action) {
  default_action_ = action;
  SANDBOX_LOGGER_DEBUG("Set default syscall action to: {}",
                       static_cast<int>(action));
}

void SecurityPolicy::set_log_violations(bool enable) {
  log_violations_ = enable;
  SANDBOX_LOGGER_DEBUG("Syscall violation logging: {}",
                       enable ? "enabled" : "disabled");
}

void SecurityPolicy::add_rule(int syscall_nr, SyscallAction action,
                              const std::string& desc) {
  // Remove existing rule for this syscall
  remove_rule(syscall_nr);

  rules_.emplace_back(syscall_nr, action, desc);

  if (action == SyscallAction::ALLOW) {
    allowed_syscalls_.insert(syscall_nr);
  }

  SANDBOX_LOGGER_DEBUG("Added syscall rule: {} -> {}",
                       SyscallRegistry::get_syscall_name(syscall_nr),
                       static_cast<int>(action));
}

void SecurityPolicy::add_rule(const std::string& syscall_name,
                              SyscallAction action, const std::string& desc) {
  int syscall_nr = SyscallRegistry::get_syscall_number(syscall_name);
  if (syscall_nr == -1) {
    SANDBOX_LOGGER_ERROR("Unknown syscall name: {}", syscall_name);
    return;
  }
  add_rule(syscall_nr, action, desc);
}

void SecurityPolicy::remove_rule(int syscall_nr) {
  auto it = std::remove_if(rules_.begin(), rules_.end(),
                           [syscall_nr](const SyscallRule& rule) {
                             return rule.syscall_nr == syscall_nr;
                           });
  rules_.erase(it, rules_.end());
  allowed_syscalls_.erase(syscall_nr);
}

void SecurityPolicy::clear_rules() {
  rules_.clear();
  allowed_syscalls_.clear();
}

void SecurityPolicy::allow_syscalls(const std::vector<int>& syscalls) {
  for (int syscall : syscalls) {
    add_rule(syscall, SyscallAction::ALLOW);
  }
}

void SecurityPolicy::deny_syscalls(const std::vector<int>& syscalls) {
  for (int syscall : syscalls) {
    add_rule(syscall, SyscallAction::DENY);
  }
}

bool SecurityPolicy::is_valid() const {
  // Check that essential syscalls are allowed
  std::vector<int> essential = {SYS_exit, SYS_exit_group};

  for (int syscall : essential) {
    bool found_allow = false;
    for (const auto& rule : rules_) {
      if (rule.syscall_nr == syscall && rule.action == SyscallAction::ALLOW) {
        found_allow = true;
        break;
      }
    }
    if (!found_allow && default_action_ != SyscallAction::ALLOW) {
      SANDBOX_LOGGER_ERROR("Essential syscall {} not allowed",
                           SyscallRegistry::get_syscall_name(syscall));
      return false;
    }
  }

  return true;
}

void SecurityPolicy::print() const {
  SANDBOX_LOGGER_INFO("=== Security Policy ===");
  SANDBOX_LOGGER_INFO("Level: {}", static_cast<int>(level_));
  SANDBOX_LOGGER_INFO("Default Action: {}", static_cast<int>(default_action_));
  SANDBOX_LOGGER_INFO("Log Violations: {}", log_violations_);
  SANDBOX_LOGGER_INFO("Rules Count: {}", rules_.size());

  for (const auto& rule : rules_) {
    std::string name = SyscallRegistry::get_syscall_name(rule.syscall_nr);
    SANDBOX_LOGGER_INFO("  {} ({}) -> {}", name, rule.syscall_nr,
                        static_cast<int>(rule.action));
  }
  SANDBOX_LOGGER_INFO("=======================");
}

SecurityPolicy SecurityPolicy::create_strict_policy() {
  SecurityPolicy policy(PolicyLevel::STRICT);
  return policy;
}

SecurityPolicy SecurityPolicy::create_moderate_policy() {
  SecurityPolicy policy(PolicyLevel::MODERATE);
  return policy;
}

SecurityPolicy SecurityPolicy::create_permissive_policy() {
  SecurityPolicy policy(PolicyLevel::PERMISSIVE);
  return policy;
}

void SecurityPolicy::load_predefined_policy(PolicyLevel level) {
  switch (level) {
    case PolicyLevel::STRICT:
      add_essential_syscalls();
      break;
    case PolicyLevel::MODERATE:
      add_essential_syscalls();
      add_io_syscalls();
      add_memory_syscalls();
      break;
    case PolicyLevel::PERMISSIVE:
      add_essential_syscalls();
      add_io_syscalls();
      add_memory_syscalls();
      add_process_syscalls();
      break;
    case PolicyLevel::CUSTOM:
      // Custom policies are loaded separately
      break;
  }
}

void SecurityPolicy::add_essential_syscalls() {
  // Process control
  allow_syscalls({SYS_exit, SYS_exit_group});

  // Basic I/O
  allow_syscalls({SYS_read, SYS_write});

  SANDBOX_LOGGER_DEBUG("Added essential syscalls");
}

void SecurityPolicy::add_io_syscalls() {
  // File operations
  allow_syscalls({SYS_open, SYS_openat, SYS_close, SYS_lseek, SYS_stat,
                  SYS_fstat, SYS_lstat, SYS_access, SYS_readv, SYS_writev});

  SANDBOX_LOGGER_DEBUG("Added I/O syscalls");
}

void SecurityPolicy::add_memory_syscalls() {
  // Memory management
  allow_syscalls(
      {SYS_mmap, SYS_munmap, SYS_mprotect, SYS_brk, SYS_madvise, SYS_msync});

  SANDBOX_LOGGER_DEBUG("Added memory management syscalls");
}

void SecurityPolicy::add_process_syscalls() {
  // Process operations (limited)
  allow_syscalls({SYS_getpid, SYS_getppid, SYS_getuid, SYS_getgid,
                  SYS_gettimeofday, SYS_clock_gettime});

  SANDBOX_LOGGER_DEBUG("Added process syscalls");
}

// SyscallRegistry implementation
void SyscallRegistry::initialize_registry() {
  if (initialized_) return;

  // Essential syscalls
  name_to_number_["exit"] = SYS_exit;
  name_to_number_["exit_group"] = SYS_exit_group;
  name_to_number_["read"] = SYS_read;
  name_to_number_["write"] = SYS_write;
  name_to_number_["open"] = SYS_open;
  name_to_number_["close"] = SYS_close;
  name_to_number_["mmap"] = SYS_mmap;
  name_to_number_["munmap"] = SYS_munmap;
  name_to_number_["brk"] = SYS_brk;
  name_to_number_["access"] = SYS_access;
  name_to_number_["getpid"] = SYS_getpid;

  // Build reverse mapping
  for (const auto& pair : name_to_number_) {
    number_to_name_[pair.second] = pair.first;
  }

  initialized_ = true;
}

int SyscallRegistry::get_syscall_number(const std::string& name) {
  initialize_registry();
  auto it = name_to_number_.find(name);
  return (it != name_to_number_.end()) ? it->second : -1;
}

std::string SyscallRegistry::get_syscall_name(int number) {
  initialize_registry();
  auto it = number_to_name_.find(number);
  return (it != number_to_name_.end()) ? it->second
                                       : "unknown_" + std::to_string(number);
}

bool SyscallRegistry::is_valid_syscall(int number) {
  initialize_registry();
  return number_to_name_.find(number) != number_to_name_.end();
}

}  // namespace security
}  // namespace sandbox
