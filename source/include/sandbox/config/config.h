#ifndef __SANDBOX_CONFIG_H__
#define __SANDBOX_CONFIG_H__

#include <string>
#include <vector>

namespace sandbox {
struct SandboxConfig {
  // Program execution
  std::string program_path;
  std::vector<std::string> program_args;
  std::string working_directory;

  // Resource limits
  size_t memory_limit_mb = 128;
  int cpu_time_limit_sec = 10;
  int wall_time_limit_sec = 15;
  int max_open_files = 64;

  // Logging
  std::string log_file_path = "sandbox.log";
  bool enable_console_logging = true;
  bool enable_debug_logging = false;

  bool enable_seccomp = true;
  std::string security_policy_level =
      "moderate";  // strict, moderate, permissive, custom
  std::string custom_policy_file = "";
  bool log_syscall_violations = true;

  // Security (for future phases)
  bool enable_ptrace = false;
  bool enable_network_isolation = false;
  // Validation
  bool is_valid() const;
  void print() const;
};

class ConfigLoader {
 public:
  static SandboxConfig load_from_file(const std::string& config_path);
  static SandboxConfig create_default();
  static bool save_to_file(const SandboxConfig& config,
                           const std::string& config_path);
};
}  // namespace sandbox

#endif  // __SANDBOX_H__
