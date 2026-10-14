#ifndef RUNNER_LINKED_ACCOUNT_STORE_H_
#define RUNNER_LINKED_ACCOUNT_STORE_H_

#include <flutter/method_channel.h>
#include <flutter/encodable_value.h>

// Stores connection metadata in the current Windows user's registry hive.
// Passwords, vault keys and session tokens must never be passed here.
void HandleLinkedAccount(
    const flutter::MethodCall<flutter::EncodableValue>& call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

#endif
