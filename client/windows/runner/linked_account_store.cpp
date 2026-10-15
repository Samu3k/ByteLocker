#include "linked_account_store.h"

#include <windows.h>
#include <string>
#include <vector>

namespace {
constexpr wchar_t kPath[] = L"Software\\ByteLocker";
constexpr wchar_t kValue[] = L"LinkedAccountV1";
constexpr DWORD kMaxBytes = 4096;
using Value = flutter::EncodableValue;
using Result = flutter::MethodResult<Value>;

struct RegistryKey {
  HKEY handle = nullptr;
  ~RegistryKey() { if (handle) RegCloseKey(handle); }
};

std::string Preference(const wchar_t* name, const std::string& fallback) {
  RegistryKey key;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kPath, 0, KEY_QUERY_VALUE, &key.handle) != ERROR_SUCCESS) return fallback;
  wchar_t value[16] = {};
  DWORD type = 0, size = sizeof(value);
  if (RegQueryValueExW(key.handle, name, nullptr, &type,
      reinterpret_cast<BYTE*>(value), &size) != ERROR_SUCCESS || type != REG_SZ ||
      size < sizeof(wchar_t) || size > sizeof(value) || size % sizeof(wchar_t) != 0 ||
      value[size / sizeof(wchar_t) - 1] != L'\0') return fallback;
  const std::wstring text(value);
  std::string narrow;
  for (const auto character : text) {
    if (character > 0x7f) return fallback;
    narrow.push_back(static_cast<char>(character));
  }
  return narrow;
}

bool IsLanguage(const std::string& value) { return value == "it" || value == "en" || value == "system"; }
bool IsTheme(const std::string& value) { return value == "dark" || value == "light" || value == "system"; }

void Settings(const flutter::MethodCall<Value>& call, Result& result) {
  if (call.method_name() == "status") {
    auto language = Preference(L"Language", "it");
    auto theme = Preference(L"Theme", "dark");
    result.Success(Value(flutter::EncodableMap{
      {Value("language"), Value(IsLanguage(language) ? language : "it")},
      {Value("theme"), Value(IsTheme(theme) ? theme : "dark")},
      {Value("biometrics"), Value(false)}, {Value("passkeys"), Value(false)}
    }));
    return;
  }
  const auto* value = call.arguments() ? std::get_if<std::string>(call.arguments()) : nullptr;
  const bool language = call.method_name() == "language";
  if (!value || !(language ? IsLanguage(*value) : IsTheme(*value))) {
    result.Error("settings_write", "Invalid preference."); return;
  }
  RegistryKey key;
  const std::wstring wide(value->begin(), value->end());
  auto status = RegCreateKeyExW(HKEY_CURRENT_USER, kPath, 0, nullptr,
      REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key.handle, nullptr);
  if (status == ERROR_SUCCESS) status = RegSetValueExW(key.handle, language ? L"Language" : L"Theme",
      0, REG_SZ, reinterpret_cast<const BYTE*>(wide.c_str()),
      static_cast<DWORD>((wide.size() + 1) * sizeof(wchar_t)));
  if (status != ERROR_SUCCESS) { result.Error("settings_write", "Could not save preference."); return; }
  result.Success();
}

void Read(Result& result) {
  RegistryKey key;
  LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, kPath, 0, KEY_QUERY_VALUE,
                                &key.handle);
  if (status == ERROR_FILE_NOT_FOUND) { result.Success(); return; }
  if (status != ERROR_SUCCESS) {
    result.Error("profile_read", "Impossibile leggere il collegamento salvato.");
    return;
  }
  DWORD type = 0, size = 0;
  status = RegQueryValueExW(key.handle, kValue, nullptr, &type, nullptr, &size);
  if (status == ERROR_FILE_NOT_FOUND) { result.Success(); return; }
  if (status != ERROR_SUCCESS || type != REG_BINARY || size == 0 ||
      size > kMaxBytes) {
    result.Error("profile_read", "Collegamento salvato non valido.");
    return;
  }
  std::vector<BYTE> bytes(size);
  status = RegQueryValueExW(key.handle, kValue, nullptr, &type, bytes.data(), &size);
  if (status != ERROR_SUCCESS || type != REG_BINARY || size == 0 ||
      size > bytes.size()) {
    result.Error("profile_read", "Impossibile leggere il collegamento salvato.");
    return;
  }
  // Dart performs strict JSON, schema, HTTPS origin and identity validation.
  result.Success(Value(std::string(reinterpret_cast<const char*>(bytes.data()),
                                   size)));
}
}  // namespace

void HandleLinkedAccount(const flutter::MethodCall<Value>& call,
                         std::unique_ptr<Result> result) {
  if (call.method_name() == "status" || call.method_name() == "theme" || call.method_name() == "language") {
    Settings(call, *result); return;
  }
  if (call.method_name() == "linkedAccount") { Read(*result); return; }
  if (call.method_name() != "saveLinkedAccount") {
    result->NotImplemented();
    return;
  }
  const auto* text = call.arguments()
      ? std::get_if<std::string>(call.arguments()) : nullptr;
  if (!text || text->empty() || text->size() > kMaxBytes) {
    result->Error("profile_write", "Collegamento non valido.");
    return;
  }
  RegistryKey key;
  LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, kPath, 0, nullptr,
      REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key.handle, nullptr);
  if (status == ERROR_SUCCESS) {
    status = RegSetValueExW(key.handle, kValue, 0, REG_BINARY,
        reinterpret_cast<const BYTE*>(text->data()),
        static_cast<DWORD>(text->size()));
  }
  if (status != ERROR_SUCCESS) {
    result->Error("profile_write", "Impossibile salvare il collegamento.");
    return;
  }
  result->Success();
}
