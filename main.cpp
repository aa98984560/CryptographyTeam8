#include <iostream>
#include <string>
#include <limits>
#include <vector>
#include <filesystem> 
#include <fstream>
#include <chrono>   // 用於效能計時

// 引入 modules 資料夾下的標頭檔
#include "modules/SHA256.h"
#include "modules/rsa.hpp"
#include "modules/serpent.hpp"

using namespace std;
namespace fs = std::filesystem;

// --- 設定資料夾常數 ---
const string DATA_DIR = "data/";      
const string MODULE_DIR = "modules/"; 
const string DEFAULT_KEY_FILE = "rsa_keypair.txt"; // 預設檔名

static RSAKey globalRSAKey;
static bool hasKey = false; 

// --- 輔助：確保 data 資料夾存在 ---
void initEnvironment() {
    if (!fs::exists(DATA_DIR)) {
        fs::create_directory(DATA_DIR);
        cout << "[系統] 已自動建立資料目錄: " << DATA_DIR << endl;
    }
}

// --- 輔助：暫停 ---
void pause() {
    cout << "\n[按 Enter 鍵繼續...]";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    cin.get();
}

// --- 輔助：列出 data 資料夾下的檔案 ---
void listDataFiles() {
    cout << "\n--- " << DATA_DIR << " 目錄下的檔案 ---" << endl;
    int count = 0;
    if (fs::exists(DATA_DIR)) {
        for (const auto& entry : fs::directory_iterator(DATA_DIR)) {
            if (!entry.is_directory()) {
                cout << entry.path().filename().string() << "\t";
                if (++count % 3 == 0) cout << endl;
            }
        }
    }
    cout << "\n--------------------------" << endl;
}

// --- 成員 D 負責：SHA-256 檔案雜湊功能 ---
void hashFile(string filePath) {
    SHA256 sha;
    // 考慮到 main 的 DATA_DIR，這裡補上路徑
    string fullPath = DATA_DIR + filePath;
    ifstream file(fullPath, ios::binary | ios::ate); 

    if (!file.is_open()) {
        cout << "[錯誤] 無法開啟檔案: " << fullPath << "，請確認檔案存在於 data/ 資料夾中。" << endl;
        return;
    }

    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    vector<char> buffer(size);
    if (file.read(buffer.data(), size)) {
        auto start = chrono::high_resolution_clock::now();

        sha.update(reinterpret_cast<const uint8_t*>(buffer.data()), size);
        std::array<uint8_t, 32> digest = sha.digest();

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double, milli> elapsed = end - start;

        cout << "\n--- SHA-256 完整性檢查結果 ---" << endl;
        cout << "檔案名稱: " << filePath << endl;
        cout << "檔案大小: " << size << " bytes" << endl;
        cout << "雜湊值  : " << SHA256::toString(digest) << endl;
        cout << "運算耗時: " << elapsed.count() << " ms" << endl;
        cout << "------------------------------" << endl;
    }
}

// --- 功能：儲存 RSA 金鑰 (支援自訂檔名) ---
void saveRSAKey(const string& filename) {
    string fullPath = DATA_DIR + filename;
    ofstream fout(fullPath);
    if (fout) {
        fout << globalRSAKey.n << endl;
        fout << globalRSAKey.e << endl;
        fout << globalRSAKey.d << endl;
        cout << "[系統] RSA 金鑰已儲存至: " << fullPath << endl;
    } else {
        cerr << "[錯誤] 無法寫入檔案！" << endl;
    }
}

// --- 功能：指定檔名讀取 RSA 金鑰 ---
bool loadRSAKey(const string& filename) {
    string fullPath = DATA_DIR + filename;
    ifstream fin(fullPath);
    if (!fin) return false;

    fin >> globalRSAKey.n >> globalRSAKey.e >> globalRSAKey.d;
    
    if (fin.fail()) return false;
    
    hasKey = true;
    return true;
}

int main() {
    #ifdef _WIN32
        system("chcp 65001");
    #endif

    initEnvironment();

    while (true) {
        #ifdef _WIN32
            system("cls");
        #else
            system("clear");
        #endif

        cout << "============================================" << endl;
        cout << "   RSA + Serpent 混合加密系統 (Team 8)" << endl;
        cout << "============================================" << endl;
        cout << "資料存放位置: ./" << DATA_DIR << endl;
        cout << "RSA 金鑰狀態: " << (hasKey ? "✅ 已載入" : "❌ 未載入") << endl;
        cout << "--------------------------------------------" << endl;
        cout << "1. 生成新 RSA 金鑰" << endl;
        cout << "2. 載入 RSA 金鑰 (手動選擇)" << endl;
        cout << "3. 加密檔案 (Sender)" << endl;
        cout << "4. 解密檔案 (Receiver)" << endl;
        cout << "5. 檔案雜湊驗證 (SHA-256)" << endl;  // <-- 新增選單
        cout << "6. 離開" << endl;                    // <-- 選項順延
        cout << "============================================" << endl;
        cout << "請輸入選項: ";

        char choice;
        cin >> choice;
        cin.ignore(numeric_limits<streamsize>::max(), '\n'); 

        if (choice == '1') {
            string customName;
            cout << "\n[設定] 請輸入金鑰儲存檔名" << endl;
            cout << "(直接按 Enter 則使用預設值: " << DEFAULT_KEY_FILE << "): ";
            getline(cin, customName);

            if (customName.empty()) {
                customName = DEFAULT_KEY_FILE;
            }

            cout << "\n[系統] 生成金鑰中 (Bits=1024)..." << endl;
            try {
                globalRSAKey = rsa_keygen(1024);
                hasKey = true;
                saveRSAKey(customName);
            } catch (const exception& e) {
                cerr << "[失敗] " << e.what() << endl;
            }
            pause();
        }
        else if (choice == '2') {
            string keyFile;
            cout << "\n--- 載入金鑰 ---" << endl;
            
            while(true) {
                cout << "請輸入金鑰檔名 (輸入 ? 查詢 " << DATA_DIR << "): ";
                getline(cin, keyFile);

                if (keyFile == "?") { listDataFiles(); continue; }
                
                if (loadRSAKey(keyFile)) {
                    cout << "\n[成功] 已從 " << DATA_DIR << keyFile << " 載入金鑰。" << endl;
                    break;
                } else {
                    cout << "[失敗] 找不到檔案或是格式錯誤，請重試。" << endl;
                }
            }
            pause();
        }
        else if (choice == '3') { 
            if (!hasKey) { cout << "\n[警告] 請先執行選項 1 或 2 載入金鑰！" << endl; pause(); continue; }

            string inFile, outFile, keyFile;
            cout << "\n--- 加密模式 ---" << endl;
            
            while (true) {
                cout << "輸入原始檔名 (輸入 ? 查詢): ";
                getline(cin, inFile);
                if (inFile == "?") { listDataFiles(); continue; }
                if (fs::exists(DATA_DIR + inFile)) break;
                cout << "[錯誤] 找不到 " << (DATA_DIR + inFile) << endl;
            }

            cout << "輸入加密後檔名 (預設 after_encrpto.serpent): ";
            getline(cin, outFile);
            if (outFile.empty()) outFile = "after_encrpto.serpent";

            cout << "輸入 Session Key 儲存檔名 (預設 session.key): ";
            getline(cin, keyFile);
            if (keyFile.empty()) keyFile = "session.key";

            cout << "[1/3] 生成並保護 Session Key..." << endl;
            mpz_class sessionKey = random_bits(256);
            mpz_class encKey = rsa_encrypt(sessionKey, globalRSAKey);
            
            ofstream kout(DATA_DIR + keyFile);
            kout << encKey.get_str();
            kout.close();

            cout << "[2/3] Serpent 加密..." << endl;
            Serpent cipher;
            cipher.setKey(sessionKey);
            
            if (cipher.encryptFile(DATA_DIR + inFile, DATA_DIR + outFile)) {
                cout << "\n[成功] 加密完成！" << endl;
                cout << "   -> 檔案位於: " << DATA_DIR << outFile << endl;
            } else {
                cout << "\n[失敗] 加密錯誤。" << endl;
            }
            pause();
        }
        else if (choice == '4') { 
            if (!hasKey) { cout << "\n[警告] 無 RSA 私鑰！" << endl; pause(); continue; }

            string encFile, decFile, keyFile;
            cout << "\n--- 解密模式 ---" << endl;
            
            while(true) {
                cout << "輸入加密檔名 (預設 after_encrpto.serpent / ? 查詢): ";
                getline(cin, encFile);
                if (encFile.empty()) encFile = "after_encrpto.serpent";
                if (encFile == "?") { listDataFiles(); continue; }
                if (fs::exists(DATA_DIR + encFile)) break;
                cout << "找不到檔案。" << endl;
            }

            cout << "輸入 Session Key 檔名 (預設 session.key): ";
            getline(cin, keyFile);
            if (keyFile.empty()) keyFile = "session.key";

            cout << "輸入解密後檔名 (預設 after_decrypto.txt): ";
            getline(cin, decFile);
            if (decFile.empty()) decFile = "after_decrypto.txt";

            ifstream kin(DATA_DIR + keyFile);
            if (!kin) { cout << "找不到金鑰檔！" << endl; pause(); continue; }
            string keyStr; kin >> keyStr;
            mpz_class sessionKey = rsa_decrypt(mpz_class(keyStr), globalRSAKey);

            cout << "[1/1] Serpent 解密..." << endl;
            Serpent cipher;
            cipher.setKey(sessionKey);
            
            if (cipher.decryptFile(DATA_DIR + encFile, DATA_DIR + decFile)) {
                cout << "\n[成功] 解密完成！" << endl;
                cout << "   -> 檔案位於: " << DATA_DIR << decFile << endl;
            } else {
                cout << "\n[失敗] 解密錯誤。" << endl;
            }
            pause();
        }
        else if (choice == '5') { // <-- 新增的 case 邏輯
            string hashFileTarget;
            cout << "\n--- 檔案完整性校驗 (SHA-256) ---" << endl;
            while(true) {
                cout << "請輸入檔案名稱 (輸入 ? 查詢 " << DATA_DIR << "): ";
                getline(cin, hashFileTarget);
                if (hashFileTarget == "?") { listDataFiles(); continue; }
                if (fs::exists(DATA_DIR + hashFileTarget)) break;
                cout << "[錯誤] 找不到檔案，請重試。" << endl;
            }
            hashFile(hashFileTarget);
            pause();
        }
        else if (choice == '6') break; // 順延
    }
    return 0;
}