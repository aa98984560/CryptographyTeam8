#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <gmpxx.h>
#include <windows.h>

// 引入成員 A 與 成員 B 的標頭檔
#include "rsa.hpp"      // 請確認路徑正確
#include "serpent.hpp" // 請確認路徑正確


// 輔助函式：建立一個測試用的檔案
void create_dummy_file(const std::string& filename) {
    std::ofstream fout(filename);
    fout << "這是一份機密文件。\n";
    fout << "This is a secret message for Serpent Algorithm testing.\n";
    fout << "RSA + Serpent Hybrid System works!";
    fout.close();
}

// 輔助函式：讀取檔案內容比較
bool compare_files(const std::string& f1, const std::string& f2) {
    std::ifstream if1(f1, std::ios::binary);
    std::ifstream if2(f2, std::ios::binary);
    
    if (!if1 || !if2) return false;

    return std::equal(std::istreambuf_iterator<char>(if1),
                      std::istreambuf_iterator<char>(),
                      std::istreambuf_iterator<char>(if2));
}

int main() {
    SetConsoleOutputCP(65001);

    std::cout << "=== 混合加密系統整合測試 (RSA + Serpent) ===\n" << std::endl;

    // 檔名設定
    std::string inputFile = "test_original.txt";
    std::string encryptedFile = "test_encrypted.serpent";
    std::string decryptedFile = "test_decrypted.txt";

    // 0. 建立測試檔案
    create_dummy_file(inputFile);
    std::cout << "[Step 0] 建立測試檔案: " << inputFile << " ... 完成" << std::endl;

    // ---------------------------------------------------------
    // 第一部分：RSA 金鑰交換 (模擬成員 A 與 成員 C 的工作)
    // ---------------------------------------------------------
    std::cout << "\n[Step 1] 正在產生 RSA 金鑰對 (可能需要幾秒鐘)..." << std::endl;
    RSAKey rsa_key = rsa_keygen(1024); // 產生 1024-bit RSA key
    std::cout << "         RSA 公鑰 (e, n) 已生成。" << std::endl;

    std::cout << "[Step 2] 產生隨機 Session Key (256 bits)..." << std::endl;
    mpz_class session_key = random_bits(256);
    std::cout << "         Session Key: " << session_key << std::endl;

    std::cout << "[Step 3] 使用 RSA 公鑰加密 Session Key..." << std::endl;
    mpz_class encrypted_session_key = rsa_encrypt(session_key, rsa_key);
    // 這裡模擬網路傳輸：把 encrypted_session_key 傳給接收者...

    std::cout << "[Step 4] 接收者使用 RSA 私鑰解密 Session Key..." << std::endl;
    mpz_class decrypted_session_key = rsa_decrypt(encrypted_session_key, rsa_key);
    
    // 驗證 RSA 是否正確
    if (session_key == decrypted_session_key) {
        std::cout << "         [RSA 驗證成功] 金鑰還原無誤！" << std::endl;
    } else {
        std::cerr << "         [RSA 驗證失敗] 金鑰不匹配！程式終止。" << std::endl;
        return 1;
    }

    // ---------------------------------------------------------
    // 第二部分：Serpent 檔案加密 (模擬成員 B 的工作)
    // ---------------------------------------------------------
    std::cout << "\n[Step 5] 初始化 Serpent 並設定金鑰..." << std::endl;
    Serpent serpentCipher;
    serpentCipher.runComponentTest();
    // 關鍵點：把 RSA 解出來的 mpz_class 丟給 Serpent
    serpentCipher.setKey(decrypted_session_key); 

    std::cout << "[Step 6] 使用 Serpent 加密檔案..." << std::endl;
    if (serpentCipher.encryptFile(inputFile, encryptedFile)) {
        std::cout << "         加密成功！輸出檔案: " << encryptedFile << std::endl;
    } else {
        std::cerr << "         加密失敗！" << std::endl;
        return 1;
    }

    std::cout << "[Step 7] 使用 Serpent 解密檔案..." << std::endl;
    // 模擬接收端：重新設定一次金鑰 (確保狀態重置)
    serpentCipher.setKey(decrypted_session_key);
    
    if (serpentCipher.decryptFile(encryptedFile, decryptedFile)) {
        std::cout << "         解密成功！輸出檔案: " << decryptedFile << std::endl;
    } else {
        std::cerr << "         解密失敗！" << std::endl;
        return 1;
    }

    // ---------------------------------------------------------
    // 第三部分：最終驗證
    // ---------------------------------------------------------
    std::cout << "\n[Step 8] 比對原始檔案與解密檔案..." << std::endl;
    if (compare_files(inputFile, decryptedFile)) {
        std::cout << "============================================" << std::endl;
        std::cout << "   恭喜！混合加密系統測試完全成功！" << std::endl;
        std::cout << "   檔案內容完全一致。" << std::endl;
        std::cout << "============================================" << std::endl;
    } else {
        std::cout << "============================================" << std::endl;
        std::cout << "   警告：檔案內容不一致，請檢查 Padding 或讀寫模式。" << std::endl;
        std::cout << "============================================" << std::endl;
    }

    // 防止視窗直接關閉
    std::cout << "\n按 Enter 鍵結束程式...";
    std::cin.get();

    return 0;
}