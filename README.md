# CryptographyTeam8
RSA用法範例:

#include <iostream>
#include "rsa.hpp"   

int main() {
    // 1. 產生 RSA 金鑰（1024 or 2048）
    RSAKey key = rsa_keygen(1024);

    // 2. 假設這是一個 Serpent 產生的 session key
    mpz_class session_key = random_bits(128);

    // 3. 用 RSA 加密 session key
    mpz_class encrypted_key = rsa_encrypt(session_key, key);

    // 4. 用 RSA 解密 session key（驗證）
    mpz_class decrypted_key = rsa_decrypt(encrypted_key, key);

    // 5. 顯示結果
    std::cout << "Original session key : " << session_key << std::endl;
    std::cout << "Encrypted key        : " << encrypted_key << std::endl;
    std::cout << "Decrypted key        : " << decrypted_key << std::endl;

    return 0;
}

編譯時用mingw64:
g++ -std=c++17 "你的程式".cpp rsa.cpp -lgmpxx -lgmp -o "執行檔名稱" (編譯時需執行rsa.cpp，rsa功能實作在裡面)
______________________________________________________________________________________________________________

serpent對稱加密使用範例:

step 1 :Serpent cipher; //將class實例化
	cipher.setKey(session_key); // 自動轉化為 33 組子金鑰(mpz_class的session key))

step 2 :cipher.encryptFile("原始檔案.jpg", "加密檔.serpent");

step 3 :cipher.decryptFile("加密檔.serpent", "還原檔案.jpg");

我有附上一個test.cpp來測試RSA和SERPENT的功能是否正常，可以試試
