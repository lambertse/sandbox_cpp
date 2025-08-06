#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <thread>

#include "sandbox/config/config.h"
#include "sandbox/core/logger.h"
#include "sandbox/core/sandbox.h"

using namespace sandbox;
class SandboxTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Initialize logger for tests
    sandbox::logger::init(sandbox::logger::LOG_LEVEL_VERBOSE,
                          [](const auto& msg) {
                            // Capture output message
                            std::cout << msg << std::endl;
                          });

    // Create basic valid configuration
    config = ConfigLoader::create_default();
    config.program_path = "/bin/echo";
    config.program_args = {"Hello", "Sandbox", "Test"};
    config.memory_limit_mb = 64;
    config.cpu_time_limit_sec = 5;
  }

  SandboxConfig config;
};

TEST_F(SandboxTest, CreateSandbox) {
  Sandbox sandbox(config);
  EXPECT_EQ(sandbox.get_status(), SandboxStatus::NOT_STARTED);
  EXPECT_FALSE(sandbox.is_running());
}

TEST_F(SandboxTest, ExecuteSimpleProgram) {
  Sandbox sandbox(config);

  ExecutionResult result = sandbox.execute();

  EXPECT_EQ(result.status, SandboxStatus::FINISHED);
  EXPECT_EQ(result.exit_code, 0);
  EXPECT_GT(result.execution_time.count(), 0);
  EXPECT_GE(result.memory_used_kb, 0);
  EXPECT_TRUE(result.error_message.empty());
}

TEST_F(SandboxTest, ExecuteNonExistentProgram) {
  config.program_path = "/nonexistent/program";
  Sandbox sandbox(config);

  ExecutionResult result = sandbox.execute();

  EXPECT_EQ(result.status, SandboxStatus::ERROR);
  EXPECT_NE(result.exit_code, 0);
  EXPECT_FALSE(result.error_message.empty());
}

TEST_F(SandboxTest, ExecuteProgramWithArguments) {
  config.program_args = {"Test", "Arguments", "123"};
  Sandbox sandbox(config);

  ExecutionResult result = sandbox.execute();

  EXPECT_EQ(result.status, SandboxStatus::FINISHED);
  EXPECT_EQ(result.exit_code, 0);
}

TEST_F(SandboxTest, StatusTransitions) {
  Sandbox sandbox(config);

  EXPECT_EQ(sandbox.get_status(), SandboxStatus::NOT_STARTED);
  EXPECT_FALSE(sandbox.is_running());

  // Execute in a separate thread to test running status
  std::thread exec_thread([&sandbox]() { sandbox.execute(); });

  // Give it a moment to start
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  exec_thread.join();

  EXPECT_EQ(sandbox.get_status(), SandboxStatus::FINISHED);
  EXPECT_FALSE(sandbox.is_running());
}

TEST_F(SandboxTest, ExecutionTiming) {
  // Use a program that takes some time
  config.program_path = "/bin/sleep";
  config.program_args = {"1"};  // Sleep for 1 second

  Sandbox sandbox(config);

  auto start = std::chrono::steady_clock::now();
  ExecutionResult result = sandbox.execute();
  auto end = std::chrono::steady_clock::now();

  auto measured_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  EXPECT_EQ(result.status, SandboxStatus::FINISHED);
  EXPECT_EQ(result.exit_code, 0);
  EXPECT_GE(result.execution_time.count(), 900);   // At least 900ms
  EXPECT_LE(result.execution_time.count(), 1500);  // At most 1500ms
  EXPECT_NEAR(result.execution_time.count(), measured_time.count(), 200);
}
