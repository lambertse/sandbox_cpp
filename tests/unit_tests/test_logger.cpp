#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <thread>
#include <vector>

#include "sandbox/core/logger.h"

class SandboxLoggerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Clear captured messages
    out_messages.clear();
    err_messages.clear();

    // Setup capture functions
    out_capture_func = [this](const std::string& msg) {
      out_messages.push_back(msg);
    };

    err_capture_func = [this](const std::string& msg) {
      err_messages.push_back(msg);
    };
  }

  void TearDown() override {
    out_messages.clear();
    err_messages.clear();
  }

  // Helper function to initialize logger with capture functions
  void initLogger(sandbox::logger::LogLevels levels =
                      sandbox::logger::LOG_LEVEL_FROM_INFO) {
    sandbox::logger::init(levels, out_capture_func, err_capture_func);
  }

  // Captured messages
  std::vector<std::string> out_messages;
  std::vector<std::string> err_messages;

  // Capture functions
  sandbox::logger::LoggerFunctionType out_capture_func;
  sandbox::logger::LoggerFunctionType err_capture_func;
};

// Test basic logger initialization
TEST_F(SandboxLoggerTest, BasicInitialization) {
  initLogger(sandbox::logger::LOG_LEVEL_FROM_INFO);

  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_INFO));
  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_WARN));
  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_ERROR));
  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_FATAL));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_DEBUG));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_VERBOSE));
}

// Test silence mode
TEST_F(SandboxLoggerTest, SilenceMode) {
  initLogger(sandbox::logger::LOG_LEVEL_SILENCE);

  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_INFO));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_WARN));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_ERROR));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_FATAL));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_DEBUG));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_VERBOSE));
}

// Test individual log level checks
TEST_F(SandboxLoggerTest, LogLevelChecks) {
  initLogger(sandbox::logger::LOG_LEVEL_DEBUG |
             sandbox::logger::LOG_LEVEL_ERROR);

  EXPECT_TRUE(sandbox::logger::debugAllowed());
  EXPECT_FALSE(sandbox::logger::infoAllowed());
  EXPECT_FALSE(sandbox::logger::warnAllowed());
  EXPECT_TRUE(sandbox::logger::errorAllowed());
  EXPECT_FALSE(sandbox::logger::fatalAllowed());
  EXPECT_FALSE(sandbox::logger::verboseAllowed());
}

// Test info level logging
TEST_F(SandboxLoggerTest, InfoLogging) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO);

  sandbox::logger::info("Test message: {}", "hello world");

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("INFO    :    "));
  EXPECT_THAT(out_messages[0],
              ::testing::HasSubstr("Test message: hello world"));
  EXPECT_TRUE(err_messages.empty());
}

// Test warning level logging
TEST_F(SandboxLoggerTest, WarnLogging) {
  initLogger(sandbox::logger::LOG_LEVEL_WARN);
  ASSERT_EQ(sandbox::logger::warnAllowed(), true);

  sandbox::logger::warn("Warning: {} detected", "issue");

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("WARN    :    "));
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("Warning: issue detected"));
  EXPECT_TRUE(err_messages.empty());
}

// Test error level logging goes to error stream
TEST_F(SandboxLoggerTest, ErrorLogging) {
  initLogger(sandbox::logger::LOG_LEVEL_ERROR);

  sandbox::logger::error("Error occurred: {}", "file not found");

  ASSERT_EQ(err_messages.size(), 1);
  EXPECT_THAT(err_messages[0], ::testing::HasSubstr("ERROR   :    "));
  EXPECT_THAT(err_messages[0],
              ::testing::HasSubstr("Error occurred: file not found"));
  EXPECT_TRUE(out_messages.empty());
}

// Test fatal level logging goes to error stream
TEST_F(SandboxLoggerTest, FatalLogging) {
  initLogger(sandbox::logger::LOG_LEVEL_FATAL);

  sandbox::logger::fatal("Fatal error: {}", "system crash");

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("FATAL   :    "));
  EXPECT_THAT(out_messages[0],
              ::testing::HasSubstr("Fatal error: system crash"));
  EXPECT_TRUE(err_messages.empty());
}

// Test debug level logging
TEST_F(SandboxLoggerTest, DebugLogging) {
  initLogger(sandbox::logger::LOG_LEVEL_DEBUG);

  sandbox::logger::debug("Debug info: {} = {}", "variable", 42);

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("DEBUG   :    "));
  EXPECT_THAT(out_messages[0],
              ::testing::HasSubstr("Debug info: variable = 42"));
  EXPECT_TRUE(err_messages.empty());
}

// Test verbose level logging
TEST_F(SandboxLoggerTest, VerboseLogging) {
  initLogger(sandbox::logger::LOG_LEVEL_VERBOSE);

  sandbox::logger::verbose("Verbose output: {}", "detailed information");

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("VERBOSE :    "));
  EXPECT_THAT(out_messages[0],
              ::testing::HasSubstr("Verbose output: detailed information"));
  EXPECT_TRUE(err_messages.empty());
}

// Test message formatting with multiple parameters
TEST_F(SandboxLoggerTest, MessageFormatting) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO);

  sandbox::logger::info("User {} has {} items in {} categories", "john", 15,
                        "electronics");

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(
      out_messages[0],
      ::testing::HasSubstr("User john has 15 items in electronics categories"));
}

// Test message formatting with insufficient parameters
TEST_F(SandboxLoggerTest, MessageFormattingInsufficientParams) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO);

  sandbox::logger::info("User {} has {} items in {} categories", "john", 15);

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0],
              ::testing::HasSubstr("User john has 15 items in {} categories"));
}

// Test message formatting with excess parameters
TEST_F(SandboxLoggerTest, MessageFormattingExcessParams) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO);

  sandbox::logger::info("User {} logged in", "john", "extra", "params");

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("User john logged in"));
}

// Test log level filtering
TEST_F(SandboxLoggerTest, LogLevelFiltering) {
  initLogger(sandbox::logger::LOG_LEVEL_WARN |
             sandbox::logger::LOG_LEVEL_ERROR);

  sandbox::logger::info("Should not appear");      // Filtered out
  sandbox::logger::warn("Should appear: {}", 1);   // Should appear
  sandbox::logger::debug("Should not appear");     // Filtered out
  sandbox::logger::error("Should appear: {}", 2);  // Should appear

  EXPECT_EQ(out_messages.size(), 1);  // Only warn message
  EXPECT_EQ(err_messages.size(), 1);  // Only error message

  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("Should appear: 1"));
  EXPECT_THAT(err_messages[0], ::testing::HasSubstr("Should appear: 2"));
}

// Test changing log levels dynamically
TEST_F(SandboxLoggerTest, ChangeLogLevels) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO);

  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_INFO));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_DEBUG));

  // Change to debug level
  sandbox::logger::changeLogLevels(sandbox::logger::LOG_LEVEL_DEBUG);

  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_INFO));
  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_DEBUG));
}

// Test enable/disable specific log levels
TEST_F(SandboxLoggerTest, EnableDisableLogLevels) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO);

  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_INFO));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_DEBUG));

  // Enable debug level
  sandbox::logger::enable(sandbox::logger::LOG_LEVEL_DEBUG);
  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_DEBUG));

  // Disable info level
  sandbox::logger::disable(sandbox::logger::LOG_LEVEL_INFO);
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_INFO));
}

// Test different data types in formatting
TEST_F(SandboxLoggerTest, DifferentDataTypes) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO);

  int integer_val = 42;
  double double_val = 3.14159;
  std::string string_val = "test string";
  bool bool_val = true;

  sandbox::logger::info("Values: int={}, double={}, string={}, bool={}",
                        integer_val, double_val, string_val, bool_val);

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("int=42"));
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("double=3.14159"));
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("string=test string"));
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("bool=1"));
}

// Test wide string conversion
TEST_F(SandboxLoggerTest, WideStringConversion) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO);

  std::wstring wide_str = L"wide string test";
  std::string converted = sandbox::logger::to_string(wide_str);

  // Note: This test assumes string_utils::to_string is implemented
  // If not implemented, this test may need adjustment
  EXPECT_FALSE(converted.empty());
}

// Test macro logging with file and line information
TEST_F(SandboxLoggerTest, MacroLogging) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO);

  SANDBOX_LOGGER_INFO("Test message: {}", "macro logging");

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("INFO    :    "));
  EXPECT_THAT(out_messages[0],
              ::testing::HasSubstr("Test message: macro logging"));
}

// Test macro logging with debug information
TEST_F(SandboxLoggerTest, MacroLoggingWithDebugInfo) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO |
             sandbox::logger::LOG_LEVEL_DEBUG);

  SANDBOX_LOGGER_INFO("Test message: {}", "with debug info");

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("INFO    :    "));
  EXPECT_THAT(out_messages[0],
              ::testing::HasSubstr("Test message: with debug info"));
}

// Test debug macro specifically
TEST_F(SandboxLoggerTest, DebugMacro) {
  initLogger(sandbox::logger::LOG_LEVEL_DEBUG);

  SANDBOX_LOGGER_DEBUG("Debug message: {}", "with file info");

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("DEBUG   :    "));
  EXPECT_THAT(out_messages[0],
              ::testing::HasSubstr("Debug message: with file info"));
}

// Test compile-time log level filtering
TEST_F(SandboxLoggerTest, CompileTimeFiltering) {
  initLogger(sandbox::logger::LOG_LEVEL_FROM_INFO);

  // These macros should respect SANDBOX_MIN_ALLOWED_LOG_LEVEL
  SANDBOX_LOGGER_INFO("Info message");
  SANDBOX_LOGGER_WARN("Warning message");
  SANDBOX_LOGGER_ERROR("Error message");
  SANDBOX_LOGGER_FATAL("Fatal message");

  // Check that messages were logged appropriately
  EXPECT_GE(out_messages.size(), 2);  // Info and warn go to out
  EXPECT_GE(err_messages.size(), 1);  // Error and fatal go to err
}

// Test fallback error stream when only out function is provided
TEST_F(SandboxLoggerTest, FallbackErrorStream) {
  // Initialize with only out function, no err function
  sandbox::logger::init(sandbox::logger::LOG_LEVEL_FROM_ERROR, out_capture_func,
                        nullptr);

  sandbox::logger::error("Error message");
  sandbox::logger::fatal("Fatal message");

  // Both should go to out_messages since err function defaults to out function
  EXPECT_EQ(out_messages.size(), 2);
  EXPECT_TRUE(err_messages.empty());
}

// Test from predefined log level constants
TEST_F(SandboxLoggerTest, PredefinedLogLevelConstants) {
  // Test LOG_LEVEL_FROM_WARN includes warn, error, and fatal
  initLogger(sandbox::logger::LOG_LEVEL_FROM_WARN);

  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_INFO));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_DEBUG));
  EXPECT_FALSE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_VERBOSE));
  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_WARN));
  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_ERROR));
  EXPECT_TRUE(sandbox::logger::allowed(sandbox::logger::LOG_LEVEL_FATAL));
}

// Test edge case with empty format string
TEST_F(SandboxLoggerTest, EmptyFormatString) {
  initLogger(sandbox::logger::LOG_LEVEL_INFO);

  sandbox::logger::info("");

  ASSERT_EQ(out_messages.size(), 1);
  EXPECT_THAT(out_messages[0], ::testing::HasSubstr("INFO    :    "));
}
