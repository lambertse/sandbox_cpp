#include <atomic>

#include "sandbox/core/logger.h"
#include "sandbox/utils/string_utils.h"

namespace sandbox {
namespace logger {

namespace {

struct Statics {
  LoggerFunctionType out = [](const std::string &) {};
  LoggerFunctionType err = [](const std::string &) {};
  std::atomic<LogLevels> allowedLevels = LOG_LEVEL_SILENCE;
};

static Statics &statics() {
  static Statics s;
  return s;
}

}  // namespace

void init(LogLevels allowedLevels, LoggerFunctionType outLogFunc,
          LoggerFunctionType errLogFunc) {
  if (outLogFunc) {
    statics().out = std::move(outLogFunc);
  }
  if (errLogFunc) {
    statics().err = std::move(errLogFunc);
  } else if (statics().out) {
    statics().err = statics().out;
  }

  changeLogLevels(allowedLevels);
}
void stopLogging() { statics().allowedLevels = LOG_LEVEL_SILENCE; }

void changeLogLevels(LogLevels allowedLevels) {
  statics().allowedLevels = allowedLevels;
}

bool allowed(LogLevel level) {
  return statics().allowedLevels.load(std::memory_order_relaxed) & level;
}

void enable(LogLevel level) { statics().allowedLevels |= level; }

void disable(LogLevel level) { statics().allowedLevels &= ~level; }

void logImpl(LogLevel filteredLevel, const std::string &msg) {
  switch (filteredLevel) {
    case LOG_LEVEL_INFO:
    case LOG_LEVEL_DEBUG:
    case LOG_LEVEL_VERBOSE:
    case LOG_LEVEL_WARN:
    case LOG_LEVEL_FATAL:
      statics().out(msg);
      break;
    default:
      statics().err(msg);
      break;
  }
}

std::string to_string(const std::wstring &arg) {
  return string_utils::to_string(arg);
}

}  // namespace logger
}  // namespace sandbox
