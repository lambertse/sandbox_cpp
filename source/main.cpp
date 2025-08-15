#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "sandbox/config/config.h"
#include "sandbox/core/logger.h"
#include "sandbox/core/sandbox.h"

using namespace sandbox;
using namespace sandbox::logger;
void print_usage(const char* program_name) {
  std::cout << "Usage: " << program_name
            << " [OPTIONS] <program_to_run> [args...]\n\n";
  std::cout << "Options:\n";
  std::cout << "  -h, --help              Show this help message\n";
  std::cout << "  -m, --memory <MB>       Memory limit in MB (default: 128)\n";
  std::cout
      << "  -t, --time <seconds>    CPU time limit in seconds (default: 10)\n";
  std::cout
      << "  -w, --wall-time <sec>   Wall time limit in seconds (default: 15)\n";
  std::cout << "  -f, --files <count>     Max open files (default: 64)\n";
  std::cout << "  -d, --debug             Enable debug logging\n";
  std::cout
      << "  -l, --log <file>        Log file path (default: sandbox.log)\n";
  std::cout << "  --no-console            Disable console logging\n";
  std::cout << "  --no-seccomp            Disable seccomp filtering\n";
  std::cout << "  -p, --policy <level>    Security policy "
               "(strict/moderate/permissive)\n";
  std::cout
      << "  --no-syscall-log        Disable syscall violation logging\n\n";
  std::cout << "Examples:\n";
  std::cout << "  " << program_name << " /bin/echo \"Hello World\"\n";
  std::cout << "  " << program_name << " -m 64 -t 5 ./my_program arg1 arg2\n";
  std::cout << "  " << program_name
            << " -p strict --no-syscall-log /usr/bin/test_program\n";
}
SandboxConfig parse_arguments(int argc, char* argv[]) {
  SandboxConfig config = ConfigLoader::create_default();
  if (argc < 2) {
    print_usage(argv[0]);
    exit(1);
  }

  std::vector<std::string> args;
  bool found_program = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg.empty()) {
      continue;  // Skip empty arguments
    }

    if (!found_program && arg[0] == '-') {
      if (arg == "-h" || arg == "--help") {
        print_usage(argv[0]);
        exit(0);
      } else if (arg == "-m" || arg == "--memory") {
        if (++i >= argc) {
          std::cerr << "Error: " << arg << " requires a value\n";
          exit(1);
        }
        config.memory_limit_mb = std::stoi(argv[i]);
      } else if (arg == "-t" || arg == "--time") {
        if (++i >= argc) {
          std::cerr << "Error: " << arg << " requires a value\n";
          exit(1);
        }
        config.cpu_time_limit_sec = std::stoi(argv[i]);
      } else if (arg == "-w" || arg == "--wall-time") {
        if (++i >= argc) {
          std::cerr << "Error: " << arg << " requires a value\n";
          exit(1);
        }
        config.wall_time_limit_sec = std::stoi(argv[i]);
      } else if (arg == "-f" || arg == "--files") {
        if (++i >= argc) {
          std::cerr << "Error: " << arg << " requires a value\n";
          exit(1);
        }
        config.max_open_files = std::stoi(argv[i]);
      } else if (arg == "-d" || arg == "--debug") {
        config.enable_debug_logging = true;
      } else if (arg == "-l" || arg == "--log") {
        if (++i >= argc) {
          std::cerr << "Error: " << arg << " requires a value\n";
          exit(1);
        }
        config.log_file_path = argv[i];
      } else if (arg == "--no-console") {
        config.enable_console_logging = false;
      } else if (arg == "--no-seccomp") {
        config.enable_seccomp = false;
      } else if (arg == "-p" || arg == "--policy") {
        if (++i >= argc) {
          std::cerr << "Error: " << arg << " requires a value\n";
          exit(1);
        }
        config.security_policy_level = argv[i];
      } else if (arg == "--no-syscall-log") {
        config.log_syscall_violations = false;
      } else {
        std::cerr << "Error: Unknown option " << arg << "\n";
        exit(1);
      }
    }
  }

  if (!found_program) {
    std::cerr << "Error: No program specified\n";
    print_usage(argv[0]);
    exit(1);
  }

  return config;
}

int main(int argc, char* argv[]) {
  // Parse command line arguments
  SandboxConfig config = parse_arguments(argc, argv);

  // Initialize logger
  LogLevel log_level =
      config.enable_debug_logging ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO;
  logger::init(
      log_level, [](const std::string& msg) { std::cout << msg << std::endl; },
      [](const std::string& msg) { std::cerr << msg << std::endl; });

  SANDBOX_LOGGER_INFO("=== C++ Sandbox Starting ===");

  // Validate configuration
  if (!config.is_valid()) {
    SANDBOX_LOGGER_INFO("Invalid configuration");
    return 1;
  }

  // Print configuration
  config.print();

  try {
    // Create and run sandbox
    Sandbox sandbox(config);
    ExecutionResult result = sandbox.execute();

    // Print results
    result.print();

    // Return appropriate exit code
    switch (result.status) {
      case SandboxStatus::FINISHED:
        SANDBOX_LOGGER_INFO("Sandbox execution completed successfully");
        return result.exit_code;
      case SandboxStatus::TIMEOUT:
        SANDBOX_LOGGER_WARN("Sandbox execution timed out");
        return 124;  // Standard timeout exit code
      case SandboxStatus::KILLED:
        SANDBOX_LOGGER_WARN("Sandbox execution was killed");
        return 125;
      case SandboxStatus::ERROR:
      default:
        SANDBOX_LOGGER_ERROR("Sandbox execution failed: " +
                             result.error_message);
        return 126;
    }

  } catch (const std::exception& e) {
    SANDBOX_LOGGER_INFO("Unhandled exception: " + std::string(e.what()));
    return 127;
  }
}
