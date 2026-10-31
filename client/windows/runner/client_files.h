#ifndef RUNNER_CLIENT_FILES_H_
#define RUNNER_CLIENT_FILES_H_
#include <flutter/method_channel.h>
#include <flutter/encodable_value.h>
void HandleClientFiles(const flutter::MethodCall<flutter::EncodableValue>& call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
#endif
