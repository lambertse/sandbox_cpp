#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>

#include "sandbox/core/logger.h"
#include "sandbox/core/sandbox.h"

namespace sandbox {

Sandbox::Sandbox(const SandboxConfig& cfg)
    : config(cfg), child_pid(-1), current_status(SandboxStatus::NOT_STARTED) {
  SANDBOX_LOGGER_INFO("Sandbox created for program: {}", config.program_path);
}

Sandbox::~Sandbox() { cleanup(); }

ExecutionResult Sandbox::execute() {
  SANDBOX_LOGGER_INFO("Starting sandbox execution");
  start_time = std::chrono::steady_clock::now();
  current_status = SandboxStatus::RUNNING;

  ExecutionResult result;
  result.status = SandboxStatus::ERROR;
  result.exit_code = -1;
  result.execution_time = std::chrono::milliseconds(0);
  result.memory_used_kb = 0;

  try {
    // Setup execution environment
    if (!setup_working_directory()) {
      result.error_message = "Failed to setup working directory";
      return result;
    }

    // Fork and execute the program
    child_pid = fork_and_exec();
    if (child_pid == -1) {
      result.error_message = "Failed to fork process";
      current_status = SandboxStatus::ERROR;
      return result;
    }

    SANDBOX_LOGGER_INFO("Child process started with PID: {}", child_pid);

    // Wait for completion
    result = wait_for_completion();

  } catch (const std::exception& e) {
    result.error_message =
        "Exception during execution: {}" + std::string(e.what());
    SANDBOX_LOGGER_ERROR(result.error_message);
    current_status = SandboxStatus::ERROR;
  }

  cleanup();
  return result;
}

bool Sandbox::setup_working_directory() {
  if (!config.working_directory.empty()) {
    try {
      std::filesystem::current_path(config.working_directory);
      SANDBOX_LOGGER_DEBUG("Changed working directory to: {}",
                           config.working_directory);
      return true;
    } catch (const std::exception& e) {
      SANDBOX_LOGGER_ERROR("Failed to change working directory: {}",
                           std::string(e.what()));
      return false;
    }
  }
  return true;
}

bool Sandbox::setup_resource_limits() {
  struct rlimit limit;

  // Memory limit
  if (config.memory_limit_mb > 0) {
    limit.rlim_cur = limit.rlim_max = config.memory_limit_mb * 1024 * 1024;
    if (setrlimit(RLIMIT_AS, &limit) != 0) {
      SANDBOX_LOGGER_ERROR("Failed to set memory limit: {}",
                           std::string(strerror(errno)));
      return false;
    }
    SANDBOX_LOGGER_DEBUG("Set memory limit to {}{}", config.memory_limit_mb,
                         "MB");
  }

  // CPU time limit
  if (config.cpu_time_limit_sec > 0) {
    limit.rlim_cur = limit.rlim_max = config.cpu_time_limit_sec;
    if (setrlimit(RLIMIT_CPU, &limit) != 0) {
      SANDBOX_LOGGER_ERROR("Failed to set CPU time limit: {}",
                           std::string(strerror(errno)));
      return false;
    }
    SANDBOX_LOGGER_DEBUG("Set CPU time limit to {}{}",
                         config.cpu_time_limit_sec, "s");
  }

  // File descriptor limit
  if (config.max_open_files > 0) {
    limit.rlim_cur = limit.rlim_max = config.max_open_files;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
      SANDBOX_LOGGER_ERROR("Failed to set file limit: ", strerror(errno));
      return false;
    }
    SANDBOX_LOGGER_DEBUG("Set file descriptor limit to {}",
                         config.max_open_files);
  }

  return true;
}

pid_t Sandbox::fork_and_exec() {
  pid_t pid = fork();

  if (pid == -1) {
    SANDBOX_LOGGER_ERROR("Fork failed: {}", strerror(errno));
    return -1;
  }

  if (pid == 0) {
    // Child process
    SANDBOX_LOGGER_DEBUG("Child process started, setting up resource limits");

    // Setup resource limits in child
    if (!setup_resource_limits()) {
      SANDBOX_LOGGER_ERROR("Failed to setup resource limits in child");
      _exit(1);
    }

    // Prepare arguments for execv
    std::vector<char*> args;
    args.push_back(const_cast<char*>(config.program_path.c_str()));

    for (const auto& arg : config.program_args) {
      args.push_back(const_cast<char*>(arg.c_str()));
    }
    args.push_back(nullptr);

    SANDBOX_LOGGER_DEBUG("Executing: {}", config.program_path);

    // Execute the program
    execv(config.program_path.c_str(), args.data());

    // If we reach here, execv failed
    SANDBOX_LOGGER_ERROR("execv failed: {}", strerror(errno));
    _exit(1);
  }

  // Parent process
  return pid;
}

ExecutionResult Sandbox::wait_for_completion() {
  ExecutionResult result;
  result.status = SandboxStatus::ERROR;
  result.exit_code = -1;

  int status;
  struct rusage usage;
  auto start = std::chrono::steady_clock::now();

  // Wait for child with resource usage
  pid_t wait_result = wait4(child_pid, &status, 0, &usage);
  auto end = std::chrono::steady_clock::now();

  result.execution_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  result.memory_used_kb = usage.ru_maxrss;  // Peak resident set size in KB

  if (wait_result == -1) {
    result.error_message = "wait4 failed: " + std::string(strerror(errno));
    SANDBOX_LOGGER_ERROR(result.error_message);
    current_status = SandboxStatus::ERROR;
    return result;
  }

  // Analyze exit status
  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
    result.status = SandboxStatus::FINISHED;
    current_status = SandboxStatus::FINISHED;
    SANDBOX_LOGGER_INFO("Program finished with exit code: {}",
                        result.exit_code);
  } else if (WIFSIGNALED(status)) {
    int signal = WTERMSIG(status);
    result.exit_code = 128 + signal;

    if (signal == SIGKILL || signal == SIGTERM) {
      result.status = SandboxStatus::KILLED;
      current_status = SandboxStatus::KILLED;
      SANDBOX_LOGGER_WARN("Program was killed by signal: {}", signal);
    } else if (signal == SIGXCPU) {
      result.status = SandboxStatus::TIMEOUT;
      current_status = SandboxStatus::TIMEOUT;
      SANDBOX_LOGGER_WARN("Program exceeded CPU time limit");
    } else {
      result.status = SandboxStatus::ERROR;
      current_status = SandboxStatus::ERROR;
      SANDBOX_LOGGER_ERROR("Program terminated by signal: {}", signal);
    }
  }

  SANDBOX_LOGGER_INFO("Execution completed - Time: {}{} ms, Memory: KB",
                      result.execution_time.count(), result.memory_used_kb);

  return result;
}

bool Sandbox::terminate() {
  if (child_pid > 0 && current_status == SandboxStatus::RUNNING) {
    SANDBOX_LOGGER_WARN("Terminating sandbox process: {}", child_pid);

    // Try SIGTERM first
    if (kill(child_pid, SIGTERM) == 0) {
      // Wait a bit for graceful shutdown
      sleep(1);

      // Check if still running
      int status;
      pid_t result = waitpid(child_pid, &status, WNOHANG);
      if (result == 0) {
        // Still running, use SIGKILL
        SANDBOX_LOGGER_WARN("Process didn't respond to SIGTERM, using SIGKILL");
        kill(child_pid, SIGKILL);
        waitpid(child_pid, &status, 0);
      }

      current_status = SandboxStatus::KILLED;
      return true;
    } else {
      SANDBOX_LOGGER_ERROR("Failed to terminate process: {}", strerror(errno));
      return false;
    }
  }
  return false;
}

void Sandbox::cleanup() {
  if (child_pid > 0) {
    // Ensure child is reaped
    int status;
    waitpid(child_pid, &status, WNOHANG);
    child_pid = -1;
  }
}

SandboxStatus Sandbox::get_status() const { return current_status; }

bool Sandbox::is_running() const {
  return current_status == SandboxStatus::RUNNING;
}

std::chrono::milliseconds Sandbox::get_execution_time() const {
  if (current_status == SandboxStatus::RUNNING) {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                                 start_time);
  }
  return std::chrono::milliseconds(0);
}

void ExecutionResult::print() const {
  std::string status_str;
  switch (status) {
    case SandboxStatus::FINISHED:
      status_str = "FINISHED";
      break;
    case SandboxStatus::TIMEOUT:
      status_str = "TIMEOUT";
      break;
    case SandboxStatus::ERROR:
      status_str = "ERROR";
      break;
    case SandboxStatus::KILLED:
      status_str = "KILLED";
      break;
    default:
      status_str = "UNKNOWN";
      break;
  }

  SANDBOX_LOGGER_INFO("=== Execution Result ===");
  SANDBOX_LOGGER_INFO("Status: {}", status_str);
  SANDBOX_LOGGER_INFO("Exit Code: {}", exit_code);
  SANDBOX_LOGGER_INFO("Execution Time: {}ms", execution_time.count());
  SANDBOX_LOGGER_INFO("Memory Used: {}KB", memory_used_kb);
  if (!error_message.empty()) {
    SANDBOX_LOGGER_INFO("Error: {}" + error_message);
  }
  SANDBOX_LOGGER_INFO("========================");
}

}  // namespace sandbox
