#ifndef __SANDBOX_SECURITY_SECCOMP_H__
#define __SANDBOX_SECURITY_SECCOMP_H__

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <sys/prctl.h>

#include "sandbox/security/policy.h"

namespace sandbox {
namespace security {

/**
 * Seccomp-BPF filter manager for syscall filtering
 */
class SeccompFilter {
 private:
  SecurityPolicy policy_;
  std::vector<struct sock_filter> filter_program_;
  bool filter_installed_;

 public:
  explicit SeccompFilter(const SecurityPolicy& policy);
  ~SeccompFilter();

  // Filter management
  bool compile_filter();
  bool install_filter();
  bool is_installed() const { return filter_installed_; }

  // Policy management
  void update_policy(const SecurityPolicy& new_policy);
  const SecurityPolicy& get_policy() const { return policy_; }

  // Static utility methods
  static bool is_seccomp_available();
  static bool enable_no_new_privs();

  // Debugging and validation
  void print_filter_stats() const;
  bool validate_filter() const;

 private:
  // BPF program compilation
  void compile_policy_to_bpf();
  void add_architecture_check();
  void add_syscall_rules();
  void add_default_action();

  // BPF instruction helpers
  void add_instruction(uint16_t code, uint32_t k, uint8_t jt = 0,
                       uint8_t jf = 0);
  void add_load_arch();
  void add_load_syscall();
  void add_return_action(SyscallAction action);
  void add_jump_if_equal(uint32_t value, uint8_t jt, uint8_t jf = 0);

  // Action conversion
  uint32_t action_to_seccomp(SyscallAction action) const;

  // Filter optimization
  void optimize_filter();
  void sort_rules_by_frequency();
};

/**
 * RAII wrapper for seccomp filter installation
 */
class SeccompGuard {
 private:
  SeccompFilter filter_;
  bool active_;

 public:
  explicit SeccompGuard(const SecurityPolicy& policy);
  ~SeccompGuard();

  // Non-copyable, non-movable
  SeccompGuard(const SeccompGuard&) = delete;
  SeccompGuard& operator=(const SeccompGuard&) = delete;
  SeccompGuard(SeccompGuard&&) = delete;
  SeccompGuard& operator=(SeccompGuard&&) = delete;

  bool is_active() const { return active_; }
  const SecurityPolicy& get_policy() const { return filter_.get_policy(); }
};

}  // namespace security
}  // namespace sandbox

#endif  // __SANDBOX_SECURITY_SECCOMP_H__
