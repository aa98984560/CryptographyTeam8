#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <gmpxx.h>
#include <filesystem> // 用於建立 data 資料夾

#include "modules/rsa.hpp"
#include "modules/serpent.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;
const std::string DATA_DIR = "data/";

// 輔助函式：建立一個測試用的檔案
void create_dummy_file(const std::string& filename) {
    std::ofstream fout(filename);
    fout << "這是一份機密文件 (Role C Integration Test)。\n";
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
    #ifdef _WIN32
        SetConsoleOutputCP(65001);
    #endif

    std::cout << "=== 混合加密系統整合測試 (RSA + Serpent) ===\n" << std::endl;

    // 0. 確保 data 資料夾存在
    if (!fs::exists(DATA_DIR)) {
        fs::create_directory(DATA_DIR);
        std::cout << "[系統] 自動建立 " << DATA_DIR << " 資料夾" << std::endl;
    }

    // 檔名設定 (全部加上 data/ 前綴)
    std::string inputFile = DATA_DIR + "test_original.txt";
    std::string encryptedFile = DATA_DIR + "test_encrypted.serpent";
    std::string decryptedFile = DATA_DIR + "test_decrypted.txt";

    create_dummy_file(inputFile);
    std::cout << "[Step 0] 建立測試檔案: " << inputFile << " ... 完成" << std::endl;

    // ---------------------------------------------------------
    // 第一部分：RSA 金鑰交換
    // ---------------------------------------------------------
    std::cout << "\n[Step 1] 正在產生 RSA 金鑰對 (1024 bits)..." << std::endl;
    RSAKey rsa_key = rsa_keygen(1024); 
    std::cout << "         RSA 公鑰 (e, n) 已生成。" << std::endl;

    std::cout << "[Step 2] 產生隨機 Session Key (256 bits)..." << std::endl;
    mpz_class session_key = random_bits(256);
    std::cout << "         Session Key: " << session_key << std::endl;

    std::cout << "[Step 3] 使用 RSA 公鑰加密 Session Key..." << std::endl;
    mpz_class encrypted_session_key = rsa_encrypt(session_key, rsa_key);

    std::cout << "[Step 4] 接收者使用 RSA 私鑰解密 Session Key..." << std::endl;
    mpz_class decrypted_session_key = rsa_decrypt(encrypted_session_key, rsa_key);
    
    if (session_key == decrypted_session_key) {
        std::cout << "         [RSA 驗證成功] 金鑰還原無誤！" << std::endl;
    } else {
        std::cerr << "         [RSA 驗證失敗] 金鑰不匹配！程式終止。" << std::endl;
        return 1;
    }

    // ---------------------------------------------------------
    // 第二部分：Serpent 檔案加密
    // ---------------------------------------------------------
    std::cout << "\n[Step 5] 初始化 Serpent 並設定金鑰..." << std::endl;
    Serpent serpentCipher;
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
    // 模擬接收端：重新設定一次金鑰
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
        std::cout << "   測試產物皆存放於 " << DATA_DIR << " 資料夾中。" << std::endl;
        std::cout << "============================================" << std::endl;
    } else {
        std::cout << "============================================" << std::endl;
        std::cout << "   警告：檔案內容不一致。" << std::endl;
        std::cout << "============================================" << std::endl;
    }

    std::cout << "\n按 Enter 鍵結束程式...";
    std::cin.get();

    return 0;
}