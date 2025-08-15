#include <errno.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>

#include "sandbox/core/logger.h"
#include "sandbox/security/seccomp.h"

namespace sandbox {
namespace security {

SeccompFilter::SeccompFilter(const SecurityPolicy& policy)
    : policy_(policy), filter_installed_(false) {
  SANDBOX_LOGGER_DEBUG("Creating seccomp filter");
}

SeccompFilter::~SeccompFilter() {
  // Note: seccomp filters cannot be removed once installed
  if (filter_installed_) {
    SANDBOX_LOGGER_DEBUG("Seccomp filter was installed (cannot be removed)");
  }
}

bool SeccompFilter::compile_filter() {
  SANDBOX_LOGGER_DEBUG("Compiling BPF filter from security policy");

  filter_program_.clear();

  try {
    compile_policy_to_bpf();
    SANDBOX_LOGGER_INFO("BPF filter compiled successfully ({} instructions)",
                        filter_program_.size());
    return true;
  } catch (const std::exception& e) {
    SANDBOX_LOGGER_ERROR("Failed to compile BPF filter: {}", e.what());
    return false;
  }
}

bool SeccompFilter::install_filter() {
  if (filter_installed_) {
    SANDBOX_LOGGER_WARN("Filter already installed");
    return true;
  }

  if (filter_program_.empty()) {
    if (!compile_filter()) {
      return false;
    }
  }

  // Enable no_new_privs to allow seccomp in unprivileged processes
  if (!enable_no_new_privs()) {
    SANDBOX_LOGGER_ERROR("Failed to set no_new_privs");
    return false;
  }

  // Install the filter
  struct sock_fprog prog = {static_cast<unsigned short>(filter_program_.size()),
                            filter_program_.data()};

  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) {
    SANDBOX_LOGGER_ERROR("Failed to install seccomp filter: {}",
                         strerror(errno));
    return false;
  }

  filter_installed_ = true;
  SANDBOX_LOGGER_INFO("Seccomp filter installed successfully");
  return true;
}

void SeccompFilter::update_policy(const SecurityPolicy& new_policy) {
  policy_ = new_policy;
  filter_program_.clear();
  // Note: Cannot update installed filters, would need new process
}

bool SeccompFilter::is_seccomp_available() {
  // Check if seccomp is available by calling with invalid arguments
  int ret = syscall(SYS_seccomp, -1, 0, nullptr);
  return (ret == -1 && errno != ENOSYS);
}

bool SeccompFilter::enable_no_new_privs() {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    SANDBOX_LOGGER_ERROR("prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
                         strerror(errno));
    return false;
  }
  SANDBOX_LOGGER_DEBUG("no_new_privs enabled");
  return true;
}

void SeccompFilter::print_filter_stats() const {
  SANDBOX_LOGGER_INFO("Filter Statistics:");
  SANDBOX_LOGGER_INFO("  Instructions: {}", filter_program_.size());
  SANDBOX_LOGGER_INFO("  Policy Rules: {}", policy_.get_rules().size());
  SANDBOX_LOGGER_INFO("  Default Action: {}",
                      static_cast<int>(policy_.get_default_action()));
  SANDBOX_LOGGER_INFO("  Installed: {}", filter_installed_);
}

bool SeccompFilter::validate_filter() const {
  // Basic validation - check filter size and policy validity
  if (filter_program_.empty()) {
    SANDBOX_LOGGER_ERROR("Filter program is empty");
    return false;
  }

  if (filter_program_.size() > 4096) {
    SANDBOX_LOGGER_ERROR("Filter program too large ({} instructions)",
                         filter_program_.size());
    return false;
  }

  return policy_.is_valid();
}

void SeccompFilter::compile_policy_to_bpf() {
  // Architecture validation
  add_architecture_check();

  // Load syscall number
  add_load_syscall();

  // Add rules for specific syscalls
  add_syscall_rules();

  // Default action
  add_default_action();
}

void SeccompFilter::add_architecture_check() {
  // Load architecture and check if it's x86_64
  add_load_arch();
  add_jump_if_equal(AUDIT_ARCH_X86_64, 1, 0);
  add_return_action(SyscallAction::KILL);  // Kill if wrong architecture
}

void SeccompFilter::add_syscall_rules() {
  const auto& rules = policy_.get_rules();

  for (const auto& rule : rules) {
    // Jump to next rule if syscall doesn't match
    uint8_t next_rule_offset = 2;
    add_jump_if_equal(rule.syscall_nr, 0, next_rule_offset);

    // This syscall matches, return the action
    add_return_action(rule.action);
  }
}

void SeccompFilter::add_default_action() {
  add_return_action(policy_.get_default_action());
}

void SeccompFilter::add_instruction(uint16_t code, uint32_t k, uint8_t jt,
                                    uint8_t jf) {
  struct sock_filter instruction = {code, jt, jf, k};
  filter_program_.push_back(instruction);
}

void SeccompFilter::add_load_arch() {
  add_instruction(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, arch));
}

void SeccompFilter::add_load_syscall() {
  add_instruction(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
}

void SeccompFilter::add_return_action(SyscallAction action) {
  add_instruction(BPF_RET | BPF_K, action_to_seccomp(action));
}

void SeccompFilter::add_jump_if_equal(uint32_t value, uint8_t jt, uint8_t jf) {
  add_instruction(BPF_JMP | BPF_JEQ | BPF_K, value, jt, jf);
}

uint32_t SeccompFilter::action_to_seccomp(SyscallAction action) const {
  switch (action) {
    case SyscallAction::ALLOW:
      return SECCOMP_RET_ALLOW;
    case SyscallAction::DENY:
      return SECCOMP_RET_ERRNO | EPERM;
    case SyscallAction::KILL:
      return SECCOMP_RET_KILL;
    case SyscallAction::TRAP:
      return SECCOMP_RET_TRAP;
    case SyscallAction::LOG:
      return SECCOMP_RET_LOG;
    default:
      return SECCOMP_RET_KILL;
  }
}

// SeccompGuard implementation
SeccompGuard::SeccompGuard(const SecurityPolicy& policy)
    : filter_(policy), active_(false) {
  if (filter_.compile_filter() && filter_.install_filter()) {
    active_ = true;
    SANDBOX_LOGGER_INFO("Seccomp guard activated");
  } else {
    SANDBOX_LOGGER_ERROR("Failed to activate seccomp guard");
  }
}

SeccompGuard::~SeccompGuard() {
  if (active_) {
    SANDBOX_LOGGER_DEBUG(
        "Seccomp guard deactivated (filter remains installed)");
  }
}

}  // namespace security
}  // namespace sandbox
