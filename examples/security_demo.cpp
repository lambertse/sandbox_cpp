/**
 * Security policy demonstration program
 * Shows different security policy levels and their effects
 */

#include <sys/syscall.h>
#include <unistd.h>

#include <iostream>
#include <vector>

#include "sandbox/core/logger.h"
#include "sandbox/security/policy.h"
#include "sandbox/security/seccomp.h"

using namespace sandbox::security;

void test_policy_level(PolicyLevel level, const std::string& level_name) {
  std::cout << "\n=== Testing " << level_name << " Policy ===\n";

  SecurityPolicy policy;

  switch (level) {
    case PolicyLevel::STRICT:
      policy = SecurityPolicy::create_strict_policy();
      break;
    case PolicyLevel::MODERATE:
      policy = SecurityPolicy::create_moderate_policy();
      break;
    case PolicyLevel::PERMISSIVE:
      policy = SecurityPolicy::create_permissive_policy();
      break;
    default:
      return;
  }

  policy.print();

  // Test syscall filtering in a child process
  pid_t pid = fork();
  if (pid == 0) {
    // Child process - install filter and test syscalls
    SeccompFilter filter(policy);

    if (!filter.install_filter()) {
      std::cerr << "Failed to install filter\n";
      _exit(1);
    }

    std::cout << "Filter installed, testing syscalls...\n";

    // Test allowed syscall
    std::cout << "Testing write (should work): ";
    if (write(STDOUT_FILENO, "OK\n", 3) > 0) {
      std::cout << "SUCCESS\n";
    }

    // Test potentially blocked syscall
    std::cout << "Testing getpid: ";
    pid_t my_pid = getpid();
    std::cout << "PID = " << my_pid << " (SUCCESS)\n";

    _exit(0);
  } else {
    // Parent process - wait for child
    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
      std::cout << "Child exited with code: " << WEXITSTATUS(status) << "\n";
    } else if (WIFSIGNALED(status)) {
      std::cout << "Child killed by signal: " << WTERMSIG(status) << "\n";
    }
  }
}

int main() {
  // Initialize logging
  sandbox::core::Logger logger("security_demo.log");

  std::cout << "Security Policy Demonstration\n";
  std::cout << "=============================\n";

  test_policy_level(PolicyLevel::STRICT, "STRICT");
  test_policy_level(PolicyLevel::MODERATE, "MODERATE");
  test_policy_level(PolicyLevel::PERMISSIVE, "PERMISSIVE");

  std::cout << "\nDemo completed!\n";
  return 0;
}
