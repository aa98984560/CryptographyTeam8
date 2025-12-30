#include "rsa.hpp"
#include <iostream>

int main() {
  try {
    // 期末 demo 建議：1024 或 2048
    RSAKey key = rsa_keygen(1024);

    // 模擬 Serpent session key（例如 128-bit）
    mpz_class session_key = random_bits(128);

    std::cout << "=== RSA Key Generated ===\n";
    std::cout << "n (bits) = " << mpz_sizeinbase(key.n.get_mpz_t(), 2) << "\n";
    std::cout << "e        = " << key.e << "\n\n";

    std::cout << "=== Hybrid Demo (RSA encrypts session key) ===\n";
    std::cout << "session_key (orig) = " << session_key << "\n";

    mpz_class enc = rsa_encrypt(session_key, key);
    std::cout << "encrypted_key      = " << enc << "\n";

    mpz_class dec = rsa_decrypt(enc, key);
    std::cout << "decrypted_key      = " << dec << "\n\n";

    if (dec == session_key) {
      std::cout << "[OK] decrypt(encrypt(session_key)) == session_key\n";
      return 0;
    } else {
      std::cout << "[FAIL] mismatch!\n";
      return 1;
    }

  } catch (const std::exception& ex) {
    std::cerr << "Error: " << ex.what() << "\n";
    return 1;
  }
}
