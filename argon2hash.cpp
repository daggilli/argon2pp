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

#include <algorithm>
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

  // ARGON_OK (0) is success. Note non-zero result internally will throw, so this either succeeds here ot terminates
  auto verifyResult = Argon2Hash::Argon2id::verify(hashString.str(), passStr);
  std::cout << std::format("VERIFY RETURNED {}, VERIFICATION {}.\n", verifyResult, (verifyResult ? "FAILED" : "SUCCEEDED"));

  // corrupt the has; this will fail and throw
  auto mangledHash = std::string(hashString.str());
  std::fill(mangledHash.begin() + 32, mangledHash.begin() + 48, 'X');
  std::cout << "MANGLED HASH: " << mangledHash << "\n";

  try {
    verifyResult = Argon2Hash::Argon2id::verify(mangledHash, passStr);
  } catch (const std::runtime_error &e) {
    std::cout << "VERIFICATION FAILED\n";
  }

  return 0;
}
