#ifndef __SANDBOX_LOGGER_H__
#define __SANDBOX_LOGGER_H__

#include <cstdint>
#include <functional>
#include <sstream>

namespace sandbox {
namespace logger {

using LogLevels = uint8_t;
using LogLevel = uint8_t;

inline constexpr LogLevel LOG_LEVEL_SILENCE = 0;
inline constexpr LogLevel LOG_LEVEL_INFO = 1;
inline constexpr LogLevel LOG_LEVEL_WARN = 2;
inline constexpr LogLevel LOG_LEVEL_ERROR = 4;
inline constexpr LogLevel LOG_LEVEL_FATAL = 8;
inline constexpr LogLevel LOG_LEVEL_DEBUG = 16;
inline constexpr LogLevel LOG_LEVEL_VERBOSE = 32;
inline constexpr LogLevel LOG_LEVEL_FROM_ERROR =
    LOG_LEVEL_ERROR | LOG_LEVEL_FATAL;
inline constexpr LogLevel LOG_LEVEL_FROM_WARN =
    LOG_LEVEL_WARN | LOG_LEVEL_FROM_ERROR;
inline constexpr LogLevel LOG_LEVEL_FROM_INFO =
    LOG_LEVEL_INFO | LOG_LEVEL_FROM_WARN;

using LoggerFunctionType = std::function<void(const std::string &msg)>;

void init(LogLevels allowedLevels = LOG_LEVEL_SILENCE,
          LoggerFunctionType outLogFunc = {},
          LoggerFunctionType errLogFunc = {});

void stopLogger();
void changeLogLevels(LogLevels allowedLevels = LOG_LEVEL_SILENCE);
bool allowed(LogLevel level);
void enable(LogLevel level);
void disable(LogLevel level);
void logImpl(LogLevel filteredLevel, const std::string &msg);

template <typename... Msg>
void debug(Msg &&...msg);
template <typename... Msg>
void info(Msg &&...msg);
template <typename... Msg>
void warn(Msg &&...msg);
template <typename... Msg>
void error(Msg &&...msg);
template <typename... Msg>
void fatal(Msg &&...msg);
template <typename... Msg>
void verbose(Msg &&...msg);
template <typename... Msg>
void log(LogLevel level, Msg &&...msg);

//--------------------------- Parser declaration----------------------------
std::string to_string(const std::wstring &arg);
template <typename T>
std::string to_string(const T &arg);
template <typename... Msg>
std::string formatMsg(Msg &&...args);

//------------------------------Implementation---------------------------------
template <typename... Msg>
void log(LogLevel level, Msg &&...msg) {
  if (allowed(level)) {
    std::string formatedStr = formatMsg(std::forward<Msg>(msg)...);
    logImpl(level, formatedStr);
  }
}
template <typename... Msg>
void debug(Msg &&...msg) {
  log(LOG_LEVEL_DEBUG, "DEBUG   :    ", std::forward<Msg>(msg)...);
}
template <typename... Msg>
void info(Msg &&...msg) {
  log(LOG_LEVEL_INFO, "INFO    :    ", std::forward<Msg>(msg)...);
}
template <typename... Msg>
void warn(Msg &&...msg) {
  log(LOG_LEVEL_WARN, "WARN    :    ", std::forward<Msg>(msg)...);
}
template <typename... Msg>
void error(Msg &&...msg) {
  log(LOG_LEVEL_ERROR, "ERROR   :    ", std::forward<Msg>(msg)...);
}
template <typename... Msg>
void fatal(Msg &&...msg) {
  log(LOG_LEVEL_FATAL, "FATAL   :    ", std::forward<Msg>(msg)...);
}
template <typename... Msg>
void verbose(Msg &&...msg) {
  log(LOG_LEVEL_VERBOSE, "VERBOSE :    ", std::forward<Msg>(msg)...);
}

template <typename T>
std::string to_string(const T &arg) {
  try {
    std::stringstream ss;
    ss << arg;
    return ss.str();
  } catch (...) {
    return "{}";
  }
}

template <typename... Msg>
std::string formatMsg(Msg &&...args) {
  std::vector<std::string> arg_strings;
  ((arg_strings.push_back(to_string(args))), ...);
  if (arg_strings.size() < 2) return "";  // Not in right format

  std::string format_string = arg_strings[1];
  std::string brace = "{}";
  size_t arg_idx = 2;

  size_t idx = 0;
  while (idx < format_string.size()) {
    int32_t found_idx = format_string.find(brace, idx);
    if (found_idx == std::string::npos) break;
    std::string replace_str = "";
    if (arg_idx < arg_strings.size()) {
      replace_str = arg_strings[arg_idx++];
    } else {
      replace_str = brace;
    }
    format_string.replace(found_idx, brace.size(), replace_str);
    idx = found_idx + replace_str.size();
  }
  return arg_strings.front() + format_string;
}

inline bool debugAllowed() { return allowed(LOG_LEVEL_DEBUG); }
inline bool infoAllowed() { return allowed(LOG_LEVEL_INFO); }
inline bool warnAllowed() { return allowed(LOG_LEVEL_WARN); }
inline bool errorAllowed() { return allowed(LOG_LEVEL_ERROR); }
inline bool fatalAllowed() { return allowed(LOG_LEVEL_FATAL); }
inline bool verboseAllowed() { return allowed(LOG_LEVEL_VERBOSE); }

using MsCStr = const char *;
inline constexpr MsCStr constexprPastLastSlash(MsCStr str, MsCStr last_slash) {
#if defined(_WINDOWS) || defined(WIN32)
  constexpr char slash = '\\';
#else
  constexpr char slash = '/';
#endif
  return *str == '\0'    ? last_slash
         : *str == slash ? constexprPastLastSlash(str + 1, str + 1)
                         : constexprPastLastSlash(str + 1, last_slash);
}

inline constexpr MsCStr constexprPastLastSlash(MsCStr str) {
  return constexprPastLastSlash(str, str);
}

}  // namespace logger
}  // namespace sandbox
//
#define SANDBOX_LOG_LEVEL_SILENCE 0
#define SANDBOX_LOG_LEVEL_DEBUG 1
#define SANDBOX_LOG_LEVEL_INFO 2
#define SANDBOX_LOG_LEVEL_WARN 4
#define SANDBOX_LOG_LEVEL_ERROR 8
#define SANDBOX_LOG_LEVEL_FATAL 16
#define SANDBOX_LOG_LEVEL_VERBOSE 32

#ifndef SANDBOX_MIN_ALLOWED_LOG_LEVEL
#define SANDBOX_MIN_ALLOWED_LOG_LEVEL SANDBOX_LOG_LEVEL_INFO
#endif

#define SANDBOX_LOGGER_DEBUG(...)                                            \
  do {                                                                       \
    if (sandbox::logger::debugAllowed()) {                                   \
      sandbox::logger::debug(__VA_ARGS__, "  --> [[ ",                       \
                             SANDBOX_SHORT_FILE_NAME, ":", __LINE__, " ]]"); \
    }                                                                        \
  } while (false)

#define SANDBOX_LOGGER_WRITE(logtype, ...)                               \
  do {                                                                   \
    if (sandbox::logger::logtype##Allowed()) {                           \
      if (!sandbox::logger::debugAllowed()) {                            \
        sandbox::logger::logtype(__VA_ARGS__);                           \
      } else {                                                           \
        sandbox::logger::logtype(__VA_ARGS__, "  --> [[ ",               \
                                 SANDBOX_SHORT_FILE_NAME, ":", __LINE__, \
                                 " ]]");                                 \
      }                                                                  \
    }                                                                    \
  } while (false)

#if SANDBOX_MIN_ALLOWED_LOG_LEVEL <= SANDBOX_LOG_LEVEL_VERBOSE
#define SANDBOX_LOGGER_VERBOSE(...) SANDBOX_LOGGER_WRITE(verbose, __VA_ARGS__)
#else
#define SANDBOX_LOGGER_VERBOSE(...) while (false)
#endif

#if SANDBOX_MIN_ALLOWED_LOG_LEVEL <= SANDBOX_LOG_LEVEL_INFO
#define SANDBOX_LOGGER_INFO(...) SANDBOX_LOGGER_WRITE(info, __VA_ARGS__)
#else
#define SANDBOX_LOGGER_INFO(...) while (false)
#endif

#if SANDBOX_MIN_ALLOWED_LOG_LEVEL <= SANDBOX_LOG_LEVEL_WARN
#define SANDBOX_LOGGER_WARN(...) SANDBOX_LOGGER_WRITE(warn, __VA_ARGS__)
#else
#define SANDBOX_LOGGER_WARN(...) while (false)
#endif

#if SANDBOX_MIN_ALLOWED_LOG_LEVEL <= SANDBOX_LOG_LEVEL_ERROR
#define SANDBOX_LOGGER_ERROR(...) SANDBOX_LOGGER_WRITE(error, __VA_ARGS__)
#else
#define SANDBOX_LOGGER_ERROR(...) while (false)
#endif

#if SANDBOX_MIN_ALLOWED_LOG_LEVEL <= SANDBOX_LOG_LEVEL_FATAL
#define SANDBOX_LOGGER_FATAL(...) SANDBOX_LOGGER_WRITE(fatal, __VA_ARGS__)
#else
#define SANDBOX_LOGGER_FATAL(...) while (false)
#endif

#define SANDBOX_SHORT_FILE_NAME \
  sandbox::logger::constexprPastLastSlash(__FILE__)

#endif  // __SANDBOX_LOGGER_H__
