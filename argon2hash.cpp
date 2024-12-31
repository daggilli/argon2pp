// Copyright (c) 2024, 2025, David Gillies
// All rights reserved.

// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

// Minimal test harness for argon2pp C++ wrapper for Argon2
// Needs libargon2 with header files, usually obtainable
// through your package manager e.g. apt install libargon2-dev
//
// Compilation:
// g++ -std=gnu++20 argon2hash.cpp -largon2 -o argon2hash
//

#include "argon2hash.h"

#include <format>
#include <iostream>
#include <sstream>
#include <string>

int main() {
  Argon2Hash::Argon2id argon;
  std::string passStr("password");
  Argon2Hash::ByteVector password = Argon2Hash::makeVector(passStr);

  auto argonHash = argon.hash(password);

  std::ostringstream hashString;
  hashString << argonHash;

  std::cout << hashString.str() << "\n";

  auto verifyResult = Argon2Hash::Argon2id::verify(hashString.str(), passStr);
  std::cout << std::format("VERIFY RETURNED {}, VERIFICATION {}.\n", verifyResult, (verifyResult ? "FAILED" : "SUCCEEDED"));
  return 0;
}
