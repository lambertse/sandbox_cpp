#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "sandbox/config/config.h"
#include "sandbox/core/logger.h"
using namespace sandbox;
class SandboxConfigTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    initLogger();

    test_executable = "/tmp/echo.tmp";  // This should exist on most systems
    // Create a simple test executable for validation
    std::ofstream ofs(test_executable);
    if (!ofs) {
      throw std::runtime_error("Failed to create test executable file");
    }
    ofs << "#!/bin/sh\necho 'Hello, Sandbox!'\n";
    ofs.close();
    // Initialize shared resources
  }

  // Runs once after all tests in this suite
  static void TearDownTestSuite() {
    // Cleanup shared resources
    // if (std::filesystem::exists(test_executable)) {
    //   std::filesystem::remove(test_executable);
    // }
  }

  static void initLogger(sandbox::logger::LogLevels levels =
                             sandbox::logger::LOG_LEVEL_FROM_INFO) {
    sandbox::logger::init(levels, [](const auto& msg) {
      // Capture output message
      std::cout << msg << std::endl;
    });
  }

  static std::string test_executable;
};
std::string SandboxConfigTest::test_executable;

TEST_F(SandboxConfigTest, DefaultConfiguration) {
  SandboxConfig config = ConfigLoader::create_default();

  EXPECT_EQ(config.memory_limit_mb, 128);
  EXPECT_EQ(config.cpu_time_limit_sec, 10);
  EXPECT_EQ(config.wall_time_limit_sec, 15);
  EXPECT_EQ(config.max_open_files, 64);
  EXPECT_EQ(config.log_file_path, "sandbox.log");
  EXPECT_TRUE(config.enable_console_logging);
  EXPECT_FALSE(config.enable_debug_logging);
  EXPECT_FALSE(config.enable_seccomp);
  EXPECT_FALSE(config.enable_ptrace);
  EXPECT_FALSE(config.enable_network_isolation);
}

TEST_F(SandboxConfigTest, ValidConfiguration) {
  SandboxConfig config = ConfigLoader::create_default();
  config.program_path = test_executable;

  EXPECT_TRUE(config.is_valid());
}

TEST_F(SandboxConfigTest, InvalidProgramPath) {
  SandboxConfig config = ConfigLoader::create_default();
  config.program_path = "/nonexistent/program";

  EXPECT_FALSE(config.is_valid());
}

TEST_F(SandboxConfigTest, EmptyProgramPath) {
  SandboxConfig config = ConfigLoader::create_default();
  config.program_path = "";

  EXPECT_FALSE(config.is_valid());
}

TEST_F(SandboxConfigTest, InvalidMemoryLimit) {
  SandboxConfig config = ConfigLoader::create_default();
  config.program_path = test_executable;
  config.memory_limit_mb = 0;

  EXPECT_FALSE(config.is_valid());

  config.memory_limit_mb = 5000;  // Too high
  EXPECT_FALSE(config.is_valid());
}

TEST_F(SandboxConfigTest, InvalidCpuTimeLimit) {
  SandboxConfig config = ConfigLoader::create_default();
  config.program_path = test_executable;
  config.cpu_time_limit_sec = 0;

  EXPECT_FALSE(config.is_valid());

  config.cpu_time_limit_sec = 400;  // Too high
  EXPECT_FALSE(config.is_valid());
}

TEST_F(SandboxConfigTest, ConfigurationWithArguments) {
  SandboxConfig config = ConfigLoader::create_default();
  config.program_path = test_executable;
  config.program_args = {"Hello", "World", "123"};

  EXPECT_TRUE(config.is_valid());
  EXPECT_EQ(config.program_args.size(), 3);
  EXPECT_EQ(config.program_args[0], "Hello");
  EXPECT_EQ(config.program_args[1], "World");
  EXPECT_EQ(config.program_args[2], "123");
}
