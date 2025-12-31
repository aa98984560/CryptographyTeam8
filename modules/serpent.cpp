/**
 * serpent.cpp
 * 實作 Serpent 演算法的核心邏輯
 * 包含：金鑰擴展、32輪加密/解密、S-Box (Bitslice模式)、檔案二進位讀寫
 */

 #include "serpent.hpp"
 #include <fstream>
 #include <iostream>
 #include <vector>
 #include <algorithm>
 #include <cstring> // for memcpy
 #include <iomanip> // 必須加這行，才能格式化輸出

void debugHex(const std::string& tag, const std::vector<uint8_t>& data) {
    std::cout << "--- [DEBUG: " << tag << "] ---" << std::endl;
    std::cout << "長度: " << data.size() << " bytes" << std::endl;
    std::cout << "內容 (Hex): ";
    for (size_t i = 0; i < data.size(); i++) {
        // 如果資料太長，只印前 32 bytes 就好，不然會洗版
        if (i >= 32) { std::cout << "..."; break; }
        printf("%02X ", data[i]);
    }
    std::cout << "\n----------------------------\n" << std::endl;
}
 
 // --- 輔助巨集：循環位移 (Rotate) ---
 // Serpent 演算法大量使用循環左移
 #define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
 #define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
 
 // --- 建構子與解構子 ---
 
 
 void Serpent::transpose(uint32_t data[4]) {
    uint32_t output[4] = {0, 0, 0, 0};
    
    // 將 128 個 bits 重新排列
    // 原始: data[i] 的第 j 個 bit
    // 目標: output[j%4] 的第 (i*32 + j)/4 ? 不，這是 4x32 轉置
    // 簡單邏輯: 把 data視為 4x32 矩陣，進行行列互換
    
    for (int i = 0; i < 128; i++) {
        // 來源: 第 (i / 32) 個整數，第 (i % 32) 個 bit
        int src_word = i / 32;
        int src_bit  = i % 32;
        
        if (data[src_word] & (1U << src_bit)) {
            // 目標: 第 (i % 4) 個整數，第 (i / 4) 個 bit
            int dst_word = i % 4;
            int dst_bit  = i / 4;
            
            output[dst_word] |= (1U << dst_bit);
        }
    }
    
    data[0] = output[0];
    data[1] = output[1];
    data[2] = output[2];
    data[3] = output[3];
}

// 逆轉置 (因為是對稱的，其實代碼跟 transpose 一模一樣，但為了語意清楚分開)
void Serpent::inverseTranspose(uint32_t data[4]) {
    uint32_t output[4] = {0, 0, 0, 0};
    
    for (int i = 0; i < 128; i++) {
        // 來源是 transpose 的目標格式
        // 來源: 第 (i % 4) 個整數，第 (i / 4) 個 bit
        int src_word = i % 4;
        int src_bit  = i / 4;
        
        // 檢查來源 bit 是否為 1
        // 注意：這裡我們遍歷 0..127 來對應 output 的填入順序
        // 我們要填入 output[i/32] 的第 i%32 bit
        
        // 讓我們換個簡單的方式：直接反過來跑 transpose 的邏輯
        // 輸入 data[dst_word] 的 dst_bit 應該回到 src_word 的 src_bit
        
        if (data[src_word] & (1U << src_bit)) {
            int dst_word = i / 32;
            int dst_bit  = i % 32;
            output[dst_word] |= (1U << dst_bit);
        }
    }
    
    data[0] = output[0];
    data[1] = output[1];
    data[2] = output[2];
    data[3] = output[3];
}
 
 // =========================================================
 //  1. 設定金鑰 (介面實作)
 // =========================================================
 void Serpent::setKey(const mpz_class& session_key) {
     // 1. 將 GMP 大數轉換為 byte vector
     std::vector<uint8_t> keyBytes;
     
     // 處理 0 的特殊情況
     if (session_key == 0) {
         keyBytes.resize(32, 0);
     } else {
         size_t count = 0;
         // mpz_export: 把大數匯出成二進位陣列
         // order=1(大端序), size=1(每次1byte), endian=1(大端), nails=0
         uint8_t* data = (uint8_t*)mpz_export(nullptr, &count, -1, 1, -1, 0, session_key.get_mpz_t());
         
         keyBytes.assign(data, data + count);
         
         // 釋放 GMP 分配的暫存記憶體
         void (*freefunc)(void *, size_t);
         mp_get_memory_functions(nullptr, nullptr, &freefunc);
         freefunc(data, count);
     }
 
     // 2. Padding: 如果不足 32 bytes (256 bits)，在前面補 0
     // Serpent 固定吃 256 bits 金鑰
     while (keyBytes.size() < 32) {
         keyBytes.insert(keyBytes.begin(), 0); 
     }
     
     // 如果超過 32 bytes (雖然不太可能，因為 RSA key 通常對應好)，只取最後 32 bytes
     if (keyBytes.size() > 32) {
          std::vector<uint8_t> temp(keyBytes.end() - 32, keyBytes.end());
          keyBytes = temp;
     }
 
     // 3. 呼叫內部核心函式進行金鑰擴展
     keySchedule(keyBytes);
 }
 
 // =========================================================
 //  2. 加密檔案 (介面實作)
 // =========================================================
 bool Serpent::encryptFile(const std::string& inputFile, const std::string& outputFile) {
     // 開啟檔案 (務必使用 std::ios::binary 以支援圖片/exe)
     std::ifstream fin(inputFile, std::ios::binary);
     std::ofstream fout(outputFile, std::ios::binary);
 
     if (!fin || !fout) {
         std::cerr << "[Error] 無法開啟檔案: " << inputFile << " 或 " << outputFile << std::endl;
         return false;
     }
 
     // 取得檔案大小
     fin.seekg(0, std::ios::end);
     size_t fileSize = fin.tellg();
     fin.seekg(0, std::ios::beg);
 
     // 讀取所有內容
     std::vector<uint8_t> buffer(fileSize);
     fin.read(reinterpret_cast<char*>(buffer.data()), fileSize);
 
     // --- PKCS#7 Padding (標準填充) ---
     // Serpent 區塊大小為 16 bytes。如果資料長度不是 16 的倍數，需要補齊。
     // 即使剛好是 16 倍數，也要補一個完整的 16 bytes block，以便解密時判斷。
     size_t paddingLen = 16 - (fileSize % 16);
     for (size_t i = 0; i < paddingLen; i++) {
         buffer.push_back((uint8_t)paddingLen);
     }
 
     // 準備輸出 buffer
     std::vector<uint8_t> encryptedData;
     encryptedData.reserve(buffer.size());
 
     uint32_t inputBlock[4];
     uint32_t outputBlock[4];
 
     // 逐區塊加密
     for (size_t i = 0; i < buffer.size(); i += 16) {
         // 1. 將 16 bytes 轉成 4 個 uint32_t (Little Endian)
         for (int j = 0; j < 4; j++) {
             inputBlock[j] = 0;
             inputBlock[j] |= (uint32_t)buffer[i + j*4 + 0];
             inputBlock[j] |= (uint32_t)buffer[i + j*4 + 1] << 8;
             inputBlock[j] |= (uint32_t)buffer[i + j*4 + 2] << 16;
             inputBlock[j] |= (uint32_t)buffer[i + j*4 + 3] << 24;
         }
 
         // 2. 核心加密
         encryptBlock(inputBlock, outputBlock);
 
         // 3. 將結果轉回 bytes
         for (int j = 0; j < 4; j++) {
             encryptedData.push_back((uint8_t)(outputBlock[j] & 0xFF));
             encryptedData.push_back((uint8_t)((outputBlock[j] >> 8) & 0xFF));
             encryptedData.push_back((uint8_t)((outputBlock[j] >> 16) & 0xFF));
             encryptedData.push_back((uint8_t)((outputBlock[j] >> 24) & 0xFF));
         }
     }
 
     // 寫入檔案
     fout.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
     debugHex("加密完成的密文", encryptedData);
     return true;
 }
 
 // =========================================================
 //  3. 解密檔案 (介面實作)
 // =========================================================
 bool Serpent::decryptFile(const std::string& inputFile, const std::string& outputFile) {
     std::ifstream fin(inputFile, std::ios::binary);
     std::ofstream fout(outputFile, std::ios::binary);
 
     if (!fin || !fout) return false;
 
     fin.seekg(0, std::ios::end);
     size_t fileSize = fin.tellg();
     fin.seekg(0, std::ios::beg);
 
     if (fileSize % 16 != 0) {
         std::cerr << "[Error] 檔案損毀：長度不是 16 的倍數。" << std::endl;
         return false;
     }
 
     std::vector<uint8_t> buffer(fileSize);
     fin.read(reinterpret_cast<char*>(buffer.data()), fileSize);
     debugHex("解密前讀到的密文", buffer);
 
     std::vector<uint8_t> decryptedData;
     decryptedData.reserve(fileSize);
 
     uint32_t inputBlock[4];
     uint32_t outputBlock[4];
 
     // 逐區塊解密
     for (size_t i = 0; i < buffer.size(); i += 16) {
         for (int j = 0; j < 4; j++) {
             inputBlock[j] = 0;
             inputBlock[j] |= (uint32_t)buffer[i + j*4 + 0];
             inputBlock[j] |= (uint32_t)buffer[i + j*4 + 1] << 8;
             inputBlock[j] |= (uint32_t)buffer[i + j*4 + 2] << 16;
             inputBlock[j] |= (uint32_t)buffer[i + j*4 + 3] << 24;
         }
 
         decryptBlock(inputBlock, outputBlock);
 
         for (int j = 0; j < 4; j++) {
             decryptedData.push_back((uint8_t)(outputBlock[j] & 0xFF));
             decryptedData.push_back((uint8_t)((outputBlock[j] >> 8) & 0xFF));
             decryptedData.push_back((uint8_t)((outputBlock[j] >> 16) & 0xFF));
             decryptedData.push_back((uint8_t)((outputBlock[j] >> 24) & 0xFF));
         }
     }
 
     // --- 移除 Padding ---
     // 讀取最後一個 byte，它代表填補了多少 bytes
     if (!decryptedData.empty()) {
        uint8_t padLen = decryptedData.back();
        std::cout << "[Debug] Padding Length detected: " << (int)padLen << std::endl;
        
        if (padLen > 0 && padLen <= 16 && padLen <= decryptedData.size()) {
            decryptedData.resize(decryptedData.size() - padLen);
        } else {
            std::cerr << "[Error] 解密後的 Padding 數值異常 (" << (int)padLen << ")，解密可能失敗！" << std::endl;
        }
    }
 
     fout.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
     return true;
 }
 
 // =========================================================
 //  核心函式：金鑰擴展 (Key Schedule)
 // =========================================================
 void Serpent::keySchedule(const std::vector<uint8_t>& key) {
     uint32_t w[140]; // 預擴展陣列
     
     // 1. 將 256 bits (32 bytes) 填入 w[0]~w[7]
     for (int i = 0; i < 8; i++) {
         w[i] = 0;
         w[i] |= (uint32_t)key[i*4 + 0];
         w[i] |= (uint32_t)key[i*4 + 1] << 8;
         w[i] |= (uint32_t)key[i*4 + 2] << 16;
         w[i] |= (uint32_t)key[i*4 + 3] << 24;
     }
 
     // 2. 使用黃金比例 (Golden Ratio) 進行擴展
     // PHI = 0x9e3779b9
     uint32_t phi = 0x9e3779b9;
     for (int i = 8; i < 140; i++) {
         // w[i] = (w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ phi ^ (i-8)) <<< 11
         uint32_t temp = w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ phi ^ (i-8);
         w[i] = ROL(temp, 11);
     }
 
     // 3. 產生 Round Keys (需經過 S-box)
     // subkeys[i] = S-box(w[i]...w[i+3])
     // Serpent 規定：Round i 使用 S-box (3 - i) % 8
     // 因為 subkeys 需要 33 組，所以要跑 33 次
     // 注意：這裡直接將 4 個 32-bit word 放入 S-box 處理 (Bitslice)
     
     uint32_t k_in[4], k_out[4];
     for (int i = 0; i < 33; i++) {
         k_in[0] = w[4*i + 8]; // 注意：Serpent文件規定從 w[8] 開始取
         k_in[1] = w[4*i + 9];
         k_in[2] = w[4*i + 10];
         k_in[3] = w[4*i + 11];
 
         // 計算對應的 S-box 索引
         int sbox_idx = (8 + 3 - (i % 8)) % 8; // 這是一個 tricky 的公式，確保順序正確
         
         applySBox(sbox_idx, k_in);
         
         // 存入 subkeys
         subkeys[i][0] = k_in[0];
         subkeys[i][1] = k_in[1];
         subkeys[i][2] = k_in[2];
         subkeys[i][3] = k_in[3];
     }
 }
 
 // =========================================================
 //  核心函式：S-Box (Bitslice Boolean Logic)
 // =========================================================
 // 這些公式來自 Serpent 官方或優化實作，透過 boolean 運算模擬 S-box 替換
 // =========================================================
//  S-Box 查表定義 (標準 Serpent S-Box)
// =========================================================
static const uint8_t SBOX[8][16] = {
    { 3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12 }, // S0
    { 15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 13, 4, 6, 3 }, // S1
    { 8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2 }, // S2
    { 0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14 }, // S3
    { 1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13 }, // S4
    { 15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1 }, // S5
    { 7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0 }, // S6
    { 1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6 }  // S7
};

static const uint8_t INV_SBOX[8][16] = {
    { 13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2 }, // InvS0
    { 5, 8, 2, 15, 13, 6, 14, 3, 11, 4, 7, 9, 1, 12, 10, 0 }, // InvS1
    { 12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7 }, // InvS2
    { 0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1 }, // InvS3
    { 5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1 }, // InvS4
    { 8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0 }, // InvS5
    { 15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11 }, // InvS6
    { 3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2 }  // InvS7
};

// =========================================================
//  applySBox (查表實作，配合 Bitslice Transpose)
// =========================================================
void Serpent::applySBox(int round, uint32_t X[4]) {
    // 因為資料已經被 Transpose 過了，所以：
    // X[0] 的第 i bit 是第 i 個 S-Box 的 input bit 0
    // X[1] 的第 i bit 是第 i 個 S-Box 的 input bit 1
    // X[2] 的第 i bit 是第 i 個 S-Box 的 input bit 2
    // X[3] 的第 i bit 是第 i 個 S-Box 的 input bit 3
    
    uint32_t Y[4] = {0, 0, 0, 0};
    int box_idx = round % 8; // 確保 index 在 0-7

    for (int i = 0; i < 32; i++) {
        // 1. 組合出 4-bit 輸入
        uint8_t input = 0;
        if (X[0] & (1U << i)) input |= 1;
        if (X[1] & (1U << i)) input |= 2;
        if (X[2] & (1U << i)) input |= 4;
        if (X[3] & (1U << i)) input |= 8;

        // 2. 查表
        uint8_t output = SBOX[box_idx][input];

        // 3. 拆解回 4-bit 輸出並填入 Y
        if (output & 1) Y[0] |= (1U << i);
        if (output & 2) Y[1] |= (1U << i);
        if (output & 4) Y[2] |= (1U << i);
        if (output & 8) Y[3] |= (1U << i);
    }

    X[0] = Y[0]; X[1] = Y[1]; X[2] = Y[2]; X[3] = Y[3];
}

// =========================================================
//  applyInverseSBox (查表實作)
// =========================================================
void Serpent::applyInverseSBox(int round, uint32_t X[4]) {
    uint32_t Y[4] = {0, 0, 0, 0};
    int box_idx = round % 8;

    for (int i = 0; i < 32; i++) {
        uint8_t input = 0;
        if (X[0] & (1U << i)) input |= 1;
        if (X[1] & (1U << i)) input |= 2;
        if (X[2] & (1U << i)) input |= 4;
        if (X[3] & (1U << i)) input |= 8;

        uint8_t output = INV_SBOX[box_idx][input];

        if (output & 1) Y[0] |= (1U << i);
        if (output & 2) Y[1] |= (1U << i);
        if (output & 4) Y[2] |= (1U << i);
        if (output & 8) Y[3] |= (1U << i);
    }

    X[0] = Y[0]; X[1] = Y[1]; X[2] = Y[2]; X[3] = Y[3];
}
 
 // =========================================================
 //  核心函式：線性變換 (Linear Transformation)
 // =========================================================
 void Serpent::linearTransform(uint32_t X[4]) {
     uint32_t x0 = X[0], x1 = X[1], x2 = X[2], x3 = X[3];
 
     x0 = ROL(x0, 13);
     x2 = ROL(x2, 3);
     x1 = x1 ^ x0 ^ x2;
     x3 = x3 ^ x2 ^ (x0 << 3);
     x1 = ROL(x1, 1);
     x3 = ROL(x3, 7);
     x0 = x0 ^ x1 ^ x3;
     x2 = x2 ^ x3 ^ (x1 << 7);
     x0 = ROL(x0, 5);
     x2 = ROL(x2, 22);
 
     X[0] = x0; X[1] = x1; X[2] = x2; X[3] = x3;
 }
 
 void Serpent::inverseLinearTransform(uint32_t X[4]) {
     uint32_t x0 = X[0], x1 = X[1], x2 = X[2], x3 = X[3];
 
     x2 = ROR(x2, 22);
     x0 = ROR(x0, 5);
     x2 = x2 ^ x3 ^ (x1 << 7);
     x0 = x0 ^ x1 ^ x3;
     x3 = ROR(x3, 7);
     x1 = ROR(x1, 1);
     x3 = x3 ^ x2 ^ (x0 << 3);
     x1 = x1 ^ x0 ^ x2;
     x2 = ROR(x2, 3);
     x0 = ROR(x0, 13);
 
     X[0] = x0; X[1] = x1; X[2] = x2; X[3] = x3;
 }
 
 // =========================================================
 //  加密單一區塊 (32 輪)
 // =========================================================
 void Serpent::encryptBlock(const uint32_t input[4], uint32_t output[4]) {
     uint32_t X[4];
     for (int i = 0; i < 4; i++) X[i] = input[i];
 
     transpose(X);

     for (int r = 0; r < 32; r++) {
         // 1. Key Mixing
         X[0] ^= subkeys[r][0];
         X[1] ^= subkeys[r][1];
         X[2] ^= subkeys[r][2];
         X[3] ^= subkeys[r][3];
 
         // 2. S-Box Substitution (Serpent 順序: S0, S1 ... S7, S0 ...)
         applySBox(r % 8, X);
 
         // 3. Linear Transformation (最後一輪 r=31 不做)
         if (r < 31) {
             linearTransform(X);
         } else {
             // 最後一輪再加一次 Key Mixing (Key 32)
             X[0] ^= subkeys[32][0];
             X[1] ^= subkeys[32][1];
             X[2] ^= subkeys[32][2];
             X[3] ^= subkeys[32][3];
         }
     }
     inverseTranspose(X);
     for (int i = 0; i < 4; i++) output[i] = X[i];
 }
 
 // =========================================================
 //  解密單一區塊 (32 輪逆向)
 // =========================================================
 void Serpent::decryptBlock(const uint32_t input[4], uint32_t output[4]) {
     uint32_t X[4];
     for (int i = 0; i < 4; i++) X[i] = input[i];
     transpose(X);
     // 最後一輪的 Key Mixing (Key 32) 先做逆運算
     X[0] ^= subkeys[32][0];
     X[1] ^= subkeys[32][1];
     X[2] ^= subkeys[32][2];
     X[3] ^= subkeys[32][3];
 
     for (int r = 31; r >= 0; r--) {
         // 1. Inverse Linear Transformation (除了最後一輪 r=31)
         if (r < 31) {
             inverseLinearTransform(X);
         }
 
         // 2. Inverse S-Box
         applyInverseSBox(r % 8, X);
 
         // 3. Key Mixing
         X[0] ^= subkeys[r][0];
         X[1] ^= subkeys[r][1];
         X[2] ^= subkeys[r][2];
         X[3] ^= subkeys[r][3];
     }
     inverseTranspose(X);
     for (int i = 0; i < 4; i++) output[i] = X[i];
     
 }
 void Serpent::runComponentTest() {
    std::cout << "\n=== Serpent 核心組件自我診斷 ===\n";
    uint32_t dummy[4] = {0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00};
    uint32_t temp[4], recover[4];

    // 1. 測試 Transpose (轉置)
    memcpy(temp, dummy, sizeof(dummy));
    transpose(temp);
    inverseTranspose(temp);
    if (memcmp(dummy, temp, sizeof(dummy)) != 0) {
        std::cerr << "[FAIL] Transpose 轉置函式無法還原！請檢查 transpose 代碼。\n";
    } else {
        std::cout << "[PASS] Transpose (轉置) 正常。\n";
    }

    // 2. 測試 Linear Transform (線性變換)
    memcpy(temp, dummy, sizeof(dummy));
    linearTransform(temp);
    inverseLinearTransform(temp);
    if (memcmp(dummy, temp, sizeof(dummy)) != 0) {
        std::cerr << "[FAIL] Linear Transform 無法還原！\n";
        // 印出數值方便除錯
        std::cerr << "Original: " << std::hex << dummy[0] << "\n";
        std::cerr << "Result  : " << std::hex << temp[0] << "\n";
    } else {
        std::cout << "[PASS] Linear Transform (線性變換) 正常。\n";
    }

    // 3. 測試 8 個 S-Box (最容易錯的地方)
    bool sbox_ok = true;
    for (int i = 0; i < 8; i++) {
        memcpy(temp, dummy, sizeof(dummy));
        applySBox(i, temp);        // 加密 S-Box
        applyInverseSBox(i, temp); // 解密 S-Box
        
        if (memcmp(dummy, temp, sizeof(dummy)) != 0) {
            std::cerr << "[FAIL] S-Box 第 " << i << " 號 無法還原！公式可能有抄寫錯誤。\n";
            sbox_ok = false;
        }
    }
    if (sbox_ok) std::cout << "[PASS] 所有 S-Box (0-7) 均正常。\n";

    std::cout << "================================\n\n";
}
 