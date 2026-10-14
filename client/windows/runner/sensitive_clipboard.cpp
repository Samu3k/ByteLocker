#include "sensitive_clipboard.h"
#include <string>
#include <variant>

namespace {
DWORD owned_sequence = 0;
HWND owner_window = nullptr;
constexpr UINT_PTR kTimer = 0x42594c43;
bool PutNoHistoryFormat(const wchar_t* name) {
  const UINT format = RegisterClipboardFormatW(name);
  if (!format) return false;
  HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, sizeof(DWORD));
  if (!memory) return false;
  if (!SetClipboardData(format, memory)) { GlobalFree(memory); return false; }
  return true;
}
void CALLBACK Expire(HWND, UINT, UINT_PTR, DWORD) { ClearSensitiveClipboard(); }
}

void ClearSensitiveClipboard() {
  if (!owned_sequence) return;
  if (!OpenClipboard(owner_window)) return; // Timer retries if another app holds it.
  if (GetClipboardSequenceNumber() == owned_sequence) EmptyClipboard();
  CloseClipboard();
  owned_sequence = 0;
  if (owner_window) KillTimer(owner_window, kTimer);
}

void HandleSensitiveClipboard(HWND window, const flutter::MethodCall<flutter::EncodableValue>& call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  if (call.method_name() == "clear") { ClearSensitiveClipboard(); result->Success(); return; }
  if (call.method_name() != "copy") { result->NotImplemented(); return; }
  const auto* text = call.arguments() ? std::get_if<std::string>(call.arguments()) : nullptr;
  if (!text || text->empty() || text->size() > 65536) { result->Error("INVALID", "Appunti non disponibili"); return; }
  const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text->data(), static_cast<int>(text->size()), nullptr, 0);
  if (!length) { result->Error("INVALID", "Appunti non disponibili"); return; }
  const SIZE_T bytes = (static_cast<SIZE_T>(length) + 1) * sizeof(wchar_t);
  HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
  if (!memory) { result->Error("UNAVAILABLE", "Appunti non disponibili"); return; }
  auto* buffer = static_cast<wchar_t*>(GlobalLock(memory));
  if (!buffer) { GlobalFree(memory); result->Error("UNAVAILABLE", "Appunti non disponibili"); return; }
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text->data(), static_cast<int>(text->size()), buffer, length);
  GlobalUnlock(memory);
  bool transferred = false;
  if (OpenClipboard(window)) {
    if (EmptyClipboard() && PutNoHistoryFormat(L"CanIncludeInClipboardHistory") && PutNoHistoryFormat(L"CanUploadToCloudClipboard")) {
      transferred = SetClipboardData(CF_UNICODETEXT, memory) != nullptr;
    }
    if (transferred) {
      owner_window = window;
      owned_sequence = GetClipboardSequenceNumber();
    }
    CloseClipboard();
  }
  if (!transferred) {
    buffer = static_cast<wchar_t*>(GlobalLock(memory));
    if (buffer) { SecureZeroMemory(buffer, bytes); GlobalUnlock(memory); }
    GlobalFree(memory);
    result->Error("UNAVAILABLE", "Appunti non disponibili"); return;
  }
  if (!SetTimer(window, kTimer, 60000, Expire)) {
    ClearSensitiveClipboard(); result->Error("UNAVAILABLE", "Appunti non disponibili"); return;
  }
  result->Success();
}
