# C++ Sandbox - Phase 1 with Examples and Tests

A beginner-friendly C++ sandbox implementation for secure program execution on Linux x86_64, complete with comprehensive examples and Google Test-based testing.

## Project Structure

```
### Core Source Files
```
source/
├── main.cpp                           # CLI interface
├── include/sandbox/
│   ├── core/
│   │   ├── sandbox.h                  # Main sandbox engine
│   │   └── logger.h                   # Logging system
│   ├── config/
│   │   └── config.h                   # Configuration management
│   └── utils/
│       └── string_utils.h             # String utilities
└── src/
    ├── core/
    │   ├── sandbox.cpp                # Sandbox implementation
    │   └── logger.cpp                 # Logger implementation
    └── config/
        └── config.cpp                 # Config implementation
```

### Example Programs
```
examples/
├── basic_usage/
│   ├── hello_world.cpp               # Simple greeting
│   ├── simple_calculator.cpp         # Math operations
│   └── file_operations.cpp           # File I/O demo
├── resource_testing/
│   ├── memory_allocator.cpp          # Memory limit testing
│   ├── cpu_intensive.cpp             # CPU time testing
│   └── file_creator.cpp              # File descriptor testing
└── malicious_simulation/
    ├── fork_bomb.cpp                 # Process limit testing
    ├── infinite_loop.cpp             # Timeout testing
    └── memory_bomb.cpp               # Memory exhaustion testing
```

### Test Suite
```
tests/
├── unit_tests/
│   ├── test_main.cpp                 # Test runner
│   ├── test_config.cpp               # Config testing
│   ├── test_logger.cpp               # Logger testing
│   └── test_sandbox.cpp              # Sandbox testing
└── integration_tests/
    ├── integration_test_main.cpp     # Integration test runner
    ├── test_resource_limits.cpp      # Resource enforcement tests
    ├── test_execution_flow.cpp       # Workflow tests
    └── test_error_handling.cpp       # Error scenario tests
```

### Build System
```
├── CMakeLists.txt                    # Main build config
├── examples/CMakeLists.txt           # Example builds
├── tests/CMakeLists.txt              # Test builds
└── build/                            # Generated build files

## Features (Phase 1)

- ✅ **Process Isolation**: Fork-exec model with resource limits
- ✅ **Resource Limiting**: Memory, CPU time, file descriptor limits
- ✅ **Comprehensive Logging**: Structured logging with timestamps
- ✅ **Execution Monitoring**: Resource usage tracking and timing
- ✅ **Clean Architecture**: Modular design ready for security enhancements
- ✅ **Example Programs**: Real-world demonstration programs
- ✅ **Unit Testing**: Google Test-based comprehensive testing

## Building

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential cmake libseccomp-dev libgtest-dev libgmock-dev

# If Google Test is not available via package manager
git clone https://github.com/google/googletest.git
cd googletest
mkdir build && cd build
cmake ..
make
sudo make install
```

### Compilation

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Installation (Optional)

```bash
sudo make install
```

## Usage

### Running the Sandbox

```bash
# Basic usage
./sandbox /bin/echo "Hello Sandbox"

# With resource limits
./sandbox -m 64 -t 5 /bin/sleep 3

# Enable debug logging
./sandbox -d -l debug.log /usr/bin/whoami
```

### Command Line Options

```
Usage: ./sandbox [OPTIONS] <program_to_run> [args...]

Options:
  -h, --help              Show help message
  -m, --memory <MB>       Memory limit in MB (default: 128)
  -t, --time <seconds>    CPU time limit in seconds (default: 10)
  -w, --wall-time <sec>   Wall time limit in seconds (default: 15)
  -f, --files <count>     Max open files (default: 64)
  -d, --debug             Enable debug logging
  -l, --log <file>        Log file path (default: sandbox.log)
  --no-console            Disable console logging
```

## Examples

### Basic Usage Examples

```bash
# Simple greeting program
./sandbox ./examples/hello_world

# Calculator with arguments
./sandbox ./examples/simple_calculator 10 5

# File operations demonstration
./sandbox ./examples/file_operations
```

### Resource Testing Examples

```bash
# Test memory limits (will be terminated by sandbox)
./sandbox -m 32 ./examples/memory_allocator

# Test CPU time limits (will timeout)
./sandbox -t 3 ./examples/cpu_intensive

# Test file descriptor limits
./sandbox -f 10 ./examples/file_creator
```

### Security Testing Examples

```bash
# Safe fork bomb simulation (limited)
./sandbox -t 5 ./examples/fork_bomb

# Infinite loop (will be terminated)
./sandbox -t 3 ./examples/infinite_loop

# Memory bomb (will hit memory limit)
./sandbox -m 16 ./examples/memory_bomb
```

## Testing

### Running All Tests

```bash
# Build and run all tests
make test

# Or use ctest directly
ctest --verbose
```

### Running Specific Test Suites

```bash
# Unit tests only
./tests/unit_tests

# Integration tests only
./tests/integration_tests

# Run with Google Test filters
./tests/unit_tests --gtest_filter="LoggerTest.*"
./tests/integration_tests --gtest_filter="ResourceLimitsTest.*"
```

### Test Coverage

The test suite includes:

#### Unit Tests
- **Logger Tests**: Log level filtering, file output, macros
- **Config Tests**: Validation, default values, edge cases
- **Sandbox Tests**: Status transitions, execution flow, error handling

#### Integration Tests
- **Resource Limits**: Memory, CPU, and file descriptor enforcement
- **Execution Flow**: Complete program execution workflows
- **Error Handling**: Invalid configurations, program crashes, edge cases

## Example Output

### Successful Execution
```
[2025-08-05 10:06:48.123] [INFO] === C++ Sandbox Starting ===
[2025-08-05 10:06:48.124] [INFO] === Sandbox Configuration ===
[2025-08-05 10:06:48.124] [INFO] Program: ./examples/hello_world
[2025-08-05 10:06:48.124] [INFO] Memory Limit: 128MB
[2025-08-05 10:06:48.124] [INFO] CPU Time Limit: 10s
[2025-08-05 10:06:48.125] [INFO] Child process started with PID: 12345
[2025-08-05 10:06:48.130] [INFO] Program finished with exit code: 0
[2025-08-05 10:06:48.131] [INFO] === Execution Result ===
[2025-08-05 10:06:48.131] [INFO] Status: FINISHED
[2025-08-05 10:06:48.131] [INFO] Exit Code: 0
[2025-08-05 10:06:48.131] [INFO] Execution Time: 5ms
[2025-08-05 10:06:48.131] [INFO] Memory Used: 1024KB
```

### Memory Limit Enforcement
```
[2025-08-05 10:06:50.123] [INFO] Starting sandbox execution
[2025-08-05 10:06:50.125] [INFO] Child process started with PID: 12346
[2025-08-05 10:06:51.200] [WARNING] Program was killed by signal: 9
[2025-08-05 10:06:51.201] [INFO] === Execution Result ===
[2025-08-05 10:06:51.201] [INFO] Status: KILLED
[2025-08-05 10:06:51.201] [INFO] Exit Code: 137
[2025-08-05 10:06:51.201] [INFO] Memory Used: 65536KB
```

## Development

### Adding New Examples

1. Create your example program in the appropriate `examples/` subdirectory
2. Add the executable target to `examples/CMakeLists.txt`
3. Document the example's purpose and expected behavior
4. Test with various sandbox configurations

### Adding New Tests

1. Create test files in `tests/unit_tests/` or `tests/integration_tests/`
2. Follow Google Test naming conventions (`TEST_F`, `TEST`)
3. Include setup and teardown as needed
4. Add new test executables to `tests/CMakeLists.txt`

### Code Style

- Follow C++17 standards
- Use RAII principles
- Include comprehensive error handling
- Document public interfaces
- Write descriptive test names

## Architecture

```
┌─────────────────┐    ┌──────────────────┐
│   Command Line  │───▶│  SandboxConfig   │
│   Interface     │    │  Configuration   │
└─────────────────┘    └──────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌──────────────────┐
│     Logger      │◀───│     Sandbox      │
│    System       │    │  Execution Engine│
└─────────────────┘    └──────────────────┘
                               │
                               ▼
                    ┌──────────────────┐
                    │  ExecutionResult │
                    │   & Statistics   │
                    └──────────────────┘
```

## What's Next?

**Phase 2** will add:
- 🔒 Syscall filtering with seccomp-bpf
- 🛡️ Basic security policies
- ⚡ Performance monitoring
- 🎛️ Enhanced resource controls

**Phase 3** will add:
- 🔍 System call tracing with ptrace
- 📁 File system monitoring
- 🌐 Network activity tracking
- 📊 Advanced logging and reporting

## Troubleshooting

### Common Issues

1. **Google Test Not Found**: Install `libgtest-dev` or build from source
2. **Permission Denied**: Ensure programs are executable (`chmod +x`)
3. **Memory Allocation Failed**: Lower memory limits or check system resources
4. **Tests Failing**: Check that dependencies are properly installed

### Debug Mode

Enable debug logging to see detailed execution flow:

```bash
./sandbox -d -l debug.log your_program
tail -f debug.log
```

### Running Individual Tests

```bash
# Test specific functionality
./tests/unit_tests --gtest_filter="LoggerTest.InitializeLogger"
./tests/integration_tests --gtest_filter="ResourceLimitsTest.MemoryLimitEnforcement"
```

## Contributing

This is a learning project! Contributions welcome:
- Add more example programs
- Improve test coverage
- Enhance error handling
- Optimize resource management
- Add performance benchmarks

---

**Phase 1 Complete** ✅  
**Examples & Tests Ready** ✅  
**Ready for Phase 2 Security Enhancements!** 🚀
