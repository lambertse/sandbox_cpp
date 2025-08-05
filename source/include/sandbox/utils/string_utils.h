#ifndef __SANDBOX_STRING_UTILS_H__
#define __SANDBOX_STRING_UTILS_H__

#include <cctype>
#include <codecvt>
#include <cwctype>
#include <locale>
namespace sandbox {
namespace string_utils {

static std::wstring_convert<std::codecvt_utf8<wchar_t> > _convertor;

template <typename T>
std::string to_string(const T& value) {
  return std::to_string(value);
}

template <>
std::string to_string(const std::wstring& value) {
  return _convertor.to_bytes(value);
}

}  // namespace string_utils
}  // namespace sandbox

#endif  // __SANDBOX_STRING_UTILS_H__
