// Copyright (c) 2024, 2025, David Gillies
// All rights reserved.

// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

#ifndef __ARGON2HASH_H__
#define __ARGON2HASH_H__
#include <argon2.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <ios>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace Argon2Hash {
  constexpr uint32_t DEFAULT_TIME_COST = 6;
  constexpr uint32_t DEFAULT_MEMORY_COST = 65536;
  constexpr uint32_t DEFAULT_PARALLELISM = 8;
  constexpr std::size_t DEFAULT_HASH_LENGTH = 64;
  constexpr std::size_t DEFAULT_SALT_LEN = 16;

  using namespace std::placeholders;

  using ByteVector = std::vector<uint8_t>;

  namespace {
    constexpr char symbols[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string base64Encode(const ByteVector &vec) {
      std::ostringstream enc;
      char outBuf[4];

      std::size_t j = 0;

      if (vec.size() >= 3)
        for (size_t i = 0; i < vec.size() / 3; i++) {
          outBuf[0] = symbols[(vec[j] >> 2) & 0b111111];
          outBuf[1] = symbols[(vec[j] & 0b11) << 4 | ((vec[j + 1] >> 4) & 0b1111)];
          outBuf[2] = symbols[(vec[j + 1] & 0b1111) << 2 | ((vec[j + 2] >> 6) & 0b11)];
          outBuf[3] = symbols[vec[j + 2] & 0b111111];
          enc.write(outBuf, 4);
          j += 3;
        }

      if (auto r = vec.size() - j) {
        outBuf[0] = symbols[(vec[j] >> 2) & 0b111111];
        if (r == 1) {
          outBuf[1] = symbols[(vec[j] & 0b11) << 4];
        } else {
          outBuf[1] = symbols[(vec[j] & 0b11) << 4 | ((vec[j + 1] >> 4) & 0b1111)];
          outBuf[2] = symbols[(vec[j + 1] & 0b1111) << 2];
        }
        enc.write(outBuf, r + 1);
      }

      return enc.str();
    }
  }  // namespace

  struct Argon2Config {
    // reasonable default values
    uint32_t timeCost = DEFAULT_TIME_COST;
    uint32_t memoryCost = DEFAULT_MEMORY_COST;
    uint32_t parallelism = DEFAULT_PARALLELISM;
    std::size_t hashLength = DEFAULT_HASH_LENGTH;
    std::size_t saltLength = DEFAULT_SALT_LEN;
  };

  using Argon2Config = struct Argon2Config;
  struct Argon2Hash {
    ByteVector hash;
    ByteVector salt;
    std::size_t timeCost;
    std::size_t memoryCost;
    std::size_t parallelism;
    argon2_version version;
    argon2_type algorithm;
    std::string algName;
  };

  using Argon2hash = struct Argon2Hash;

  constexpr Argon2Config ARGON2_CONFIG_DEFAULT{};

  std::ostream &operator<<(std::ostream &os, const Argon2Hash &argon) {
    os << std::dec << "$" << argon.algName << "$v=" << argon.version << "$m=" << argon.memoryCost << ",t=" << argon.timeCost
       << ",p=" << argon.parallelism << "$" << base64Encode(argon.salt) << "$" << base64Encode(argon.hash);
    return os;
  }

  using Argon2RawHashFunction = std::function<int(const uint32_t, const uint32_t, const uint32_t, const void *, const size_t,
                                                  const void *, const size_t, void *, const size_t)>;
  using Argon2HashFunction = std::function<int(const void *, const size_t, const void *, const size_t, void *, const size_t)>;

  class Argon2 {
   public:
    Argon2Hash hash(const ByteVector &message) {
      ByteVector saltVec = makeSalt(saltLen);

      ByteVector hashVec(hashLen);
      auto hashResult = hasher(message.data(), message.size(), saltVec.data(), saltLen, hashVec.data(), hashLen);

      if (hashResult != ARGON2_OK) {
        std::string errMessage = "Argon2i hash failed: ";
        std::throw_with_nested(std::runtime_error(errMessage + argon2_error_message(hashResult)));
      }

      return {std::move(hashVec), std::move(saltVec), tc, mc, prl, argon2_version::ARGON2_VERSION_NUMBER, algorithm, algName};
    }

    Argon2Hash hash(const ByteVector &message, const ByteVector &salt) {
      ByteVector hashVec(hashLen);
      auto hashResult = hasher(message.data(), message.size(), salt.data(), salt.size(), hashVec.data(), hashLen);

      if (hashResult != ARGON2_OK) {
        std::string errMessage = "Argon2i hash failed: ";
        std::throw_with_nested(std::runtime_error(errMessage + argon2_error_message(hashResult)));
      }

      return {std::move(hashVec), ByteVector(salt), tc, mc, prl, argon2_version::ARGON2_VERSION_NUMBER, algorithm, algName};
    }

    Argon2Hash hash(const std::string &message) {
      ByteVector saltVec = makeSalt(saltLen);

      ByteVector hashVec(hashLen);
      auto hashResult = hasher(message.data(), message.length(), saltVec.data(), saltLen, hashVec.data(), hashLen);

      if (hashResult != ARGON2_OK) {
        std::string errMessage = Argon2::algDesc[algorithm] + " hash failed: ";
        std::throw_with_nested(std::runtime_error(errMessage + argon2_error_message(hashResult)));
      }

      return {std::move(hashVec), std::move(saltVec), tc, mc, prl, argon2_version::ARGON2_VERSION_NUMBER, algorithm, algName};
    }

    Argon2Hash hash(const std::string &message, const ByteVector &salt) {
      ByteVector hashVec(hashLen);
      auto hashResult = hasher(message.data(), message.length(), salt.data(), salt.size(), hashVec.data(), hashLen);

      if (hashResult != ARGON2_OK) {
        std::string errMessage = Argon2::algDesc[algorithm] + " hash failed: ";
        std::throw_with_nested(std::runtime_error(errMessage + argon2_error_message(hashResult)));
      }

      return {std::move(hashVec), ByteVector(salt), tc, mc, prl, argon2_version::ARGON2_VERSION_NUMBER, algorithm, algName};
    }

    Argon2Hash hash(const std::string &message, const std::string &salt) {
      ByteVector hashVec(hashLen);
      auto hashResult = hasher(message.data(), message.length(), salt.data(), salt.length(), hashVec.data(), hashLen);

      if (hashResult != ARGON2_OK) {
        std::string errMessage = Argon2::algDesc[algorithm] + " hash failed: ";
        std::throw_with_nested(std::runtime_error(errMessage + argon2_error_message(hashResult)));
      }

      return {std::move(hashVec),
              ByteVector(salt.data(), salt.data() + salt.size()),
              tc,
              mc,
              prl,
              argon2_version::ARGON2_VERSION_NUMBER,
              algorithm,
              algName};
    }

   protected:
    Argon2(Argon2RawHashFunction rawFunction, const argon2_type alg, const std::string &name, const Argon2Config &conf)
        : tc(conf.timeCost),
          mc(conf.memoryCost),
          prl(conf.parallelism),
          hashLen(conf.hashLength),
          saltLen(conf.saltLength),
          algorithm(alg),
          algName(name),
          hasher(std::bind(rawFunction, conf.timeCost, conf.memoryCost, conf.parallelism, _1, _2, _3, _4, _5, _6)) {}

    static int verify(const std::string &encodedHash, const std::string &message, const argon2_type alg) {
      auto verifyResult = argon2_verify(encodedHash.c_str(), message.data(), message.length(), alg);

      if (verifyResult != ARGON2_OK) {
        std::string errMessage = Argon2::algDesc[alg] + " verify failed: ";
        std::throw_with_nested(std::runtime_error(errMessage + argon2_error_message(verifyResult)));
      }

      return verifyResult;
    }

    uint32_t tc;
    uint32_t mc;
    uint32_t prl;
    std::size_t hashLen;
    std::size_t saltLen;
    argon2_type algorithm;
    std::string algName;
    Argon2HashFunction hasher;

   private:
    ByteVector makeSalt(const std::size_t saltLen) {
      ByteVector saltVec(saltLen);

      std::random_device rd;
      std::generate(saltVec.begin(), saltVec.end(), [&rd]() -> uint8_t { return static_cast<uint8_t>(rd()); });

      return saltVec;
    }

    inline static std::string algDesc[] = {"Argon2i", "Argon2d", "Argon2id"};
  };

  class Argon2d : public Argon2 {
   public:
    Argon2d() : Argon2(argon2d_hash_raw, Argon2_d, "argon2d", ARGON2_CONFIG_DEFAULT) {}
    Argon2d(const Argon2Config &conf) : Argon2(argon2d_hash_raw, Argon2_d, "argon2d", conf) {}
    static int verify(const std::string &encoded, const std::string &message) {
      return Argon2::verify(encoded, message, Argon2_d);
    }
  };

  class Argon2i : public Argon2 {
   public:
    Argon2i() : Argon2(argon2i_hash_raw, Argon2_i, "argon2i", ARGON2_CONFIG_DEFAULT) {}
    Argon2i(const Argon2Config &conf) : Argon2(argon2i_hash_raw, Argon2_i, "argon2i", conf) {}
    static int verify(const std::string &encoded, const std::string &message) {
      return Argon2::verify(encoded, message, Argon2_i);
    }
  };

  class Argon2id : public Argon2 {
   public:
    Argon2id() : Argon2(argon2id_hash_raw, Argon2_id, "argon2id", ARGON2_CONFIG_DEFAULT) {}
    Argon2id(const Argon2Config &conf) : Argon2(argon2id_hash_raw, Argon2_id, "argon2id", conf) {}
    static int verify(const std::string &encoded, const std::string &message) {
      return Argon2::verify(encoded, message, Argon2_id);
    }
  };

  static ByteVector makeVector(const std::string &str) {
    ByteVector vec;
    vec.resize(str.length());
    vec.assign(str.data(), str.data() + str.length());

    return vec;
  }
}  // namespace Argon2Hash
#endif
