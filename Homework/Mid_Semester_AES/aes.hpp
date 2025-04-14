#ifndef AES_HPP
#define AES_HPP

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstring>

// Các hằng số AES
#define AES_BLOCK_SIZE 16 // 128 bit
#define Nb 4              // Số lượng cột trong State
#define Nk 4              // Số lượng từ khóa 32-bit (AES-128)
#define Nr 10             // Số round (AES-128)

// Các bảng tra cứu
extern const unsigned char sbox[256];
extern const unsigned char inv_sbox[256];
extern const unsigned char rcon[11];

// Các kiểu dữ liệu
typedef unsigned char byte;
typedef byte state_t[4][4];

// Các hàm thư viện cho AES
namespace AES {
    // Các hàm chung
    void AddRoundKey(state_t &state, const byte* round_key);
    
    void KeyExpansion(const byte* key, byte* expanded_key);
    byte GaloisMultiply(byte a, byte b);
    
    // Các hàm mã hóa
    void SubBytes(state_t &state);
    void ShiftRows(state_t &state);
    void MixColumns(state_t &state);
    void Cipher(byte* input, byte* output, const byte* expanded_key);
    
    // Các hàm giải mã
    void InvSubBytes(state_t &state);
    void InvShiftRows(state_t &state);
    void InvMixColumns(state_t &state);
    void InvCipher(byte* input, byte* output, const byte* expanded_key);
    
    // Các hàm tiện ích
    void EncryptFile(const std::string& input_file, const std::string& output_file, const byte* key);
    void DecryptFile(const std::string& input_file, const std::string& output_file, const byte* key);
    void PrintHex(const byte* data, int len);
    void PrintState(const state_t& state);
}

#endif