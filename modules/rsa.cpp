#include "rsa.hpp"
#include <stdexcept>
#include <ctime>

static gmp_randclass& global_rng() {
  static gmp_randclass rng(gmp_randinit_default);
  static bool seeded = false;
  if (!seeded) {
    // 期末作業 demo 用時間 seed（可用 /dev/urandom 改更安全）
    rng.seed(static_cast<unsigned long>(std::time(nullptr)));
    seeded = true;
  }
  return rng;
}

mpz_class random_bits(std::size_t bits) {
  if (bits == 0) return 0;
  mpz_class x = global_rng().get_z_bits(bits);
  // 確保最高位為 1，避免實際位數不足
  x |= (mpz_class(1) << (bits - 1));
  return x;
}

//產生質數
static mpz_class next_prime_of_bits(std::size_t bits) {
  mpz_class x = random_bits(bits);
  mpz_nextprime(x.get_mpz_t(), x.get_mpz_t());
  return x;
}

//RSA的key生成
RSAKey rsa_keygen(std::size_t bits) {
  if (bits < 256) {
    throw std::invalid_argument("bits too small (use 1024 or 2048).");
  }

  const std::size_t half = bits / 2;
  //生成p、q兩個質數
  mpz_class p = next_prime_of_bits(half);
  mpz_class q = next_prime_of_bits(bits - half);

  // 避免 p == q（雖然機率低）
  while (p == q) {
    q = next_prime_of_bits(bits - half);
  }

  mpz_class n   = p * q;
  //phi=φ(n)
  mpz_class phi = (p - 1) * (q - 1);

  // 常用公開指數，
  mpz_class e = 65537;

  // 確保 gcd(e, phi) == 1，不然 d 會不存在
  mpz_class g;
  mpz_gcd(g.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
  if (g != 1) {
    // 若不互質，就改用隨機奇數 e（demo 夠用）
    do {
      e = global_rng().get_z_range(phi - 2) + 2; // [2, phi)
      if (e % 2 == 0) e += 1;
      mpz_gcd(g.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
    } while (g != 1);
  }

  // d = e^{-1} mod phi
  mpz_class d;
  if (mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t()) == 0) {
    throw std::runtime_error("mpz_invert failed: e has no inverse mod phi.");
  }

  RSAKey key;
  key.n = n;
  key.e = e;
  key.d = d;
  return key;
}

mpz_class rsa_encrypt(const mpz_class& m, const RSAKey& key) {
  if (m < 0) throw std::invalid_argument("message must be non-negative.");
  if (m >= key.n) throw std::invalid_argument("message must be < n.");
  mpz_class c;
  //mpz_powm為GMP的mod指數運算
  mpz_powm(c.get_mpz_t(), m.get_mpz_t(), key.e.get_mpz_t(), key.n.get_mpz_t());
  return c;
}

mpz_class rsa_decrypt(const mpz_class& c, const RSAKey& key) {
  if (c < 0) throw std::invalid_argument("cipher must be non-negative.");
  if (c >= key.n) throw std::invalid_argument("cipher must be < n.");
  mpz_class m;
  mpz_powm(m.get_mpz_t(), c.get_mpz_t(), key.d.get_mpz_t(), key.n.get_mpz_t());
  return m;
}
