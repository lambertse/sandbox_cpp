#ifndef __SANDBOX_SECURITY_POLICY_H__
#define __SANDBOX_SECURITY_POLICY_H__

#include <sys/syscall.h>

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace sandbox {
namespace security {

/**
 * Syscall action to take when a syscall is encountered
 */
enum class SyscallAction {
  ALLOW,  // Allow the syscall to proceed
  DENY,   // Deny with EPERM error
  KILL,   // Kill the process
  TRAP,   // Generate SIGSYS signal
  LOG     // Log the syscall attempt and allow
};

/**
 * Predefined security policy levels
 */
enum class PolicyLevel {
  STRICT,      // Minimal syscalls only (read/write/exit)
  MODERATE,    // Basic file I/O and memory operations
  PERMISSIVE,  // Most common syscalls allowed
  CUSTOM       // User-defined policy
};

/**
 * Individual syscall rule
 */
struct SyscallRule {
  int syscall_nr;
  SyscallAction action;
  std::string description;

  SyscallRule(int nr, SyscallAction act, const std::string& desc = "")
      : syscall_nr(nr), action(act), description(desc) {}
};

/**
 * Security policy containing syscall rules and configuration
 */
class SecurityPolicy {
 private:
  PolicyLevel level_;
  SyscallAction default_action_;
  std::vector<SyscallRule> rules_;
  std::unordered_set<int> allowed_syscalls_;
  bool log_violations_;

 public:
  SecurityPolicy(PolicyLevel level = PolicyLevel::MODERATE);

  // Policy configuration
  void set_policy_level(PolicyLevel level);
  void set_default_action(SyscallAction action);
  void set_log_violations(bool enable);

  // Rule management
  void add_rule(int syscall_nr, SyscallAction action,
                const std::string& desc = "");
  void add_rule(const std::string& syscall_name, SyscallAction action,
                const std::string& desc = "");
  void remove_rule(int syscall_nr);
  void clear_rules();

  // Bulk operations
  void allow_syscalls(const std::vector<int>& syscalls);
  void deny_syscalls(const std::vector<int>& syscalls);

  // Query methods
  PolicyLevel get_level() const { return level_; }
  SyscallAction get_default_action() const { return default_action_; }
  bool get_log_violations() const { return log_violations_; }
  const std::vector<SyscallRule>& get_rules() const { return rules_; }

  // Policy validation and info
  bool is_valid() const;
  void print() const;

  // Factory methods for predefined policies
  static SecurityPolicy create_strict_policy();
  static SecurityPolicy create_moderate_policy();
  static SecurityPolicy create_permissive_policy();

 private:
  void load_predefined_policy(PolicyLevel level);
  void add_essential_syscalls();
  void add_io_syscalls();
  void add_memory_syscalls();
  void add_process_syscalls();
};

/**
 * Syscall name to number conversion utilities
 */
class SyscallRegistry {
 public:
  static int get_syscall_number(const std::string& name);
  static std::string get_syscall_name(int number);
  static bool is_valid_syscall(int number);
  static std::vector<std::string> get_all_syscall_names();

 private:
  static void initialize_registry();
  static std::unordered_map<std::string, int> name_to_number_;
  static std::unordered_map<int, std::string> number_to_name_;
  static bool initialized_;
};

}  // namespace security
}  // namespace sandbox

#endif  // __SANDBOX_SECURITY_POLICY_H__
