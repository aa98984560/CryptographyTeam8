#ifndef SERPENT_HPP
#define SERPENT_HPP

#include <string>
#include <vector>
#include <cstdint>  // 為了使用 uint8_t, uint32_t (密碼學必備)
#include <gmpxx.h>  // 為了接收成員 A 的 mpz_class 金鑰

class Serpent {
public:
    // --- 建構子與解構子 ---
    Serpent() { std::memset(subkeys, 0, sizeof(subkeys)); }
    ~Serpent() { std::memset(subkeys, 0, sizeof(subkeys)); }

    // --- 給成員 C 呼叫的主要介面 ---

    // 1. 設定金鑰
    // 功能：接收成員 A 解密出來的 Session Key (mpz_class)，轉成 Serpent 用的 256-bit 金鑰
    void setKey(const mpz_class& session_key);

    // 2. 加密檔案
    // 功能：讀取 inputFile，加密後寫入 outputFile，string代表路徑
    // 回傳：true 代表成功，false 代表檔案讀寫失敗
    bool encryptFile(const std::string& inputFile, const std::string& outputFile);

    // 3. 解密檔案 (驗證用)
    // 功能：讀取加密檔，解密後還原成原始檔案，string代表路徑
    bool decryptFile(const std::string& inputFile, const std::string& outputFile);

    void runComponentTest();

private:
    // --- Serpent 內部核心變數 ---
    // 儲存擴展後的 33 組輪金鑰 (每組 128 bits = 4 * 32 bits)
    uint32_t subkeys[33][4];

    // --- Serpent 內部核心函式 (不給外部呼叫) ---

    // 金鑰擴展 (Key Schedule): 將 256-bit 主金鑰擴展成 132 個 32-bit 字組
    void keySchedule(const std::vector<uint8_t>& key);

    // 加密一個區塊 (128 bits)
    // input: 4 個 32-bit 整數, output: 4 個 32-bit 整數
    void encryptBlock(const uint32_t input[4], uint32_t output[4]);

    // 解密一個區塊 (128 bits)
    void decryptBlock(const uint32_t input[4], uint32_t output[4]);

    // S-Box 替換與逆替換 (S0~S7)
    // 這裡通常會用到你寫好的 S-box 陣列
    void applySBox(int round, uint32_t X[4]);
    void applyInverseSBox(int round, uint32_t X[4]);

    // 線性變換 (Linear Transformation)
    void linearTransform(uint32_t X[4]);
    void inverseLinearTransform(uint32_t X[4]);
    void transpose(uint32_t data[4]);
    void inverseTranspose(uint32_t data[4]);
};

#endif // SERPENT_HPP