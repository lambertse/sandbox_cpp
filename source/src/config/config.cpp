#include <filesystem>

#include "sandbox/config/config.h"
#include "sandbox/core/logger.h"

namespace sandbox {

bool SandboxConfig::is_valid() const {
  if (program_path.empty()) {
    SANDBOX_LOGGER_ERROR("Program path is empty");
    return false;
  }

  if (!std::filesystem::exists(program_path)) {
    SANDBOX_LOGGER_ERROR("Program does not exist: " + program_path);
    return false;
  }

  if (memory_limit_mb == 0 || memory_limit_mb > 4096) {
    SANDBOX_LOGGER_ERROR(
        "Invalid memory limit: " + std::to_string(memory_limit_mb) + "MB");
    return false;
  }

  if (cpu_time_limit_sec <= 0 || cpu_time_limit_sec > 300) {
    SANDBOX_LOGGER_ERROR(
        "Invalid CPU time limit: " + std::to_string(cpu_time_limit_sec) + "s");
    return false;
  }

  return true;
}

void SandboxConfig::print() const {
  SANDBOX_LOGGER_INFO("=== Sandbox Configuration ===");
  SANDBOX_LOGGER_INFO("Program: {}", program_path);
  SANDBOX_LOGGER_INFO("Working Directory: {}", working_directory);
  SANDBOX_LOGGER_INFO("Memory Limit: {}{}", memory_limit_mb, "MB");
  SANDBOX_LOGGER_INFO("CPU Time Limit: {}{}", cpu_time_limit_sec, "s");
  SANDBOX_LOGGER_INFO("Wall Time Limit: {}{}", wall_time_limit_sec, "s");
  SANDBOX_LOGGER_INFO("Max Open Files: {}", max_open_files);
  SANDBOX_LOGGER_INFO("==============================");
}

SandboxConfig ConfigLoader::create_default() {
  SandboxConfig config;
  config.working_directory = "/tmp";
  config.memory_limit_mb = 128;
  config.cpu_time_limit_sec = 10;
  config.wall_time_limit_sec = 15;
  config.max_open_files = 64;
  config.log_file_path = "sandbox.log";
  config.enable_console_logging = true;
  config.enable_debug_logging = false;

  return config;
}

// Note: JSON parsing will be added in later phases for simplicity
SandboxConfig ConfigLoader::load_from_file(const std::string& config_path) {
  SANDBOX_LOGGER_INFO("Loading configuration from: " + config_path);
  // For Phase 1, return default config
  // In later phases, we'll add JSON parsing
  return create_default();
}

bool ConfigLoader::save_to_file(const SandboxConfig& config,
                                const std::string& config_path) {
  SANDBOX_LOGGER_INFO("Saving configuration to: " + config_path);
  // For Phase 1, just return true
  // In later phases, we'll add JSON serialization
  return true;
}

}  // namespace sandbox
