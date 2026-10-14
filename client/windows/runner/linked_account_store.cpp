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
