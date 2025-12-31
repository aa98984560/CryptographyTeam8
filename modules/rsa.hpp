#ifndef RSA_HPP
#define RSA_HPP

#include <gmpxx.h>
#include <cstddef>

struct RSAKey {
  mpz_class n;  // modulus
  mpz_class e;  // public exponent
  mpz_class d;  // private exponent
};

// 產生 RSA 金鑰（bits 建議 1024/2048）
RSAKey rsa_keygen(std::size_t bits);

// RSA: c = m^e mod n
mpz_class rsa_encrypt(const mpz_class& m, const RSAKey& key);

// RSA: m = c^d mod n
mpz_class rsa_decrypt(const mpz_class& c, const RSAKey& key);

// 工具：把位元字串/小型 key 轉成 mpz_class（可用於 session key）
mpz_class random_bits(std::size_t bits);

#endif
