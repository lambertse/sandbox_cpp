#ifndef __SANDBOX_H__
#define __SANDBOX_H__
#include <sys/types.h>

#include <chrono>
#include <string>

#include "sandbox/config/config.h"
namespace sandbox {
enum class SandboxStatus {
  NOT_STARTED,
  RUNNING,
  FINISHED,
  TIMEOUT,
  ERROR,
  KILLED
};

struct ExecutionResult {
  SandboxStatus status;
  int exit_code;
  std::chrono::milliseconds execution_time;
  size_t memory_used_kb;
  std::string error_message;

  void print() const;
};

class Sandbox {
 private:
  SandboxConfig config;
  pid_t child_pid;
  SandboxStatus current_status;
  std::chrono::steady_clock::time_point start_time;

  // Internal methods
  bool setup_resource_limits();
  bool setup_working_directory();
  pid_t fork_and_exec();
  ExecutionResult wait_for_completion();
  void cleanup();

 public:
  Sandbox(const SandboxConfig& cfg);
  ~Sandbox();

  // Main interface
  ExecutionResult execute();
  bool terminate();
  SandboxStatus get_status() const;

  // Status queries
  bool is_running() const;
  std::chrono::milliseconds get_execution_time() const;
};
}  // namespace sandbox
#endif  // SANDBOX_H
