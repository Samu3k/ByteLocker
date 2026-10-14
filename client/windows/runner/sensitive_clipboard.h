#ifndef BYTELOCKER_SENSITIVE_CLIPBOARD_H_
#define BYTELOCKER_SENSITIVE_CLIPBOARD_H_
#include <windows.h>
#include <flutter/method_channel.h>
#include <flutter/encodable_value.h>
void HandleSensitiveClipboard(HWND window, const flutter::MethodCall<flutter::EncodableValue>& call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
void ClearSensitiveClipboard();
#endif
