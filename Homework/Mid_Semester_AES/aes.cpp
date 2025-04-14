#include "AES.hpp"

// Bảng S-box
const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Bảng inverse S-box
const unsigned char inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Bảng round constants
const unsigned char rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

namespace AES {
    // Thực hiện phép nhân trong trường GF(2^8)
    byte GaloisMultiply(byte a, byte b) {
        byte result = 0;
        byte high_bit;
        
        for (int i = 0; i < 8; i++) {
            if (b & 1) {
                result ^= a;
            }
            
            high_bit = (a & 0x80);
            a <<= 1;
            if (high_bit) {
                a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
            }
            
            b >>= 1;
        }
        
        return result;
    }

    // Thay thế bytes bằng S-box
    void SubBytes(state_t &state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = sbox[state[i][j]];
            }
        }
    }

    // Thực hiện phép dịch hàng
    void ShiftRows(state_t &state) {
        byte temp;
        
        // Hàng 1 - Dịch 1 vị trí
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;
        
        // Hàng 2 - Dịch 2 vị trí
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;
        
        // Hàng 3 - Dịch 3 vị trí
        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;
    }

    // Thực hiện phép trộn cột
    void MixColumns(state_t &state) {
        byte temp[4];
        
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                temp[i] = state[i][j];
            }
            
            state[0][j] = GaloisMultiply(0x02, temp[0]) ^ GaloisMultiply(0x03, temp[1]) ^ temp[2] ^ temp[3];
            state[1][j] = temp[0] ^ GaloisMultiply(0x02, temp[1]) ^ GaloisMultiply(0x03, temp[2]) ^ temp[3];
            state[2][j] = temp[0] ^ temp[1] ^ GaloisMultiply(0x02, temp[2]) ^ GaloisMultiply(0x03, temp[3]);
            state[3][j] = GaloisMultiply(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ GaloisMultiply(0x02, temp[3]);
        }
    }

    // Thực hiện phép XOR state với khóa round
    void AddRoundKey(state_t &state, const byte* round_key) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] ^= round_key[i + 4 * j];
            }
        }
    }

    // Mở rộng khóa
    void KeyExpansion(const byte* key, byte* expanded_key) {
        byte temp[4];
        int i = 0;
        
        // Sao chép khóa ban đầu vào expanded_key
        while (i < 4 * Nk) {
            expanded_key[i] = key[i];
            i++;
        }
        
        i = Nk;
        
        while (i < Nb * (Nr + 1)) {
            for (int j = 0; j < 4; j++) {
                temp[j] = expanded_key[(i - 1) * 4 + j];
            }
            
            if (i % Nk == 0) {
                // Phép dịch vòng
                byte k = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = k;
                
                // SubBytes
                for (int j = 0; j < 4; j++) {
                    temp[j] = sbox[temp[j]];
                }
                
                temp[0] ^= rcon[i / Nk];
            }
            
            for (int j = 0; j < 4; j++) {
                expanded_key[i * 4 + j] = expanded_key[(i - Nk) * 4 + j] ^ temp[j];
            }
            
            i++;
        }
    }

    // Hàm ngược của SubBytes
    void InvSubBytes(state_t &state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = inv_sbox[state[i][j]];
            }
        }
    }

    // Hàm ngược của ShiftRows
    void InvShiftRows(state_t &state) {
        byte temp;
        
        // Hàng 1 - Dịch 1 vị trí về bên phải
        temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;
        
        // Hàng 2 - Dịch 2 vị trí
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;
        
        // Hàng 3 - Dịch 3 vị trí về bên phải (1 vị trí về bên trái)
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
    }

    // Hàm ngược của MixColumns
    void InvMixColumns(state_t &state) {
        byte temp[4];
        
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                temp[i] = state[i][j];
            }
            
            state[0][j] = GaloisMultiply(0x0e, temp[0]) ^ GaloisMultiply(0x0b, temp[1]) ^ 
                          GaloisMultiply(0x0d, temp[2]) ^ GaloisMultiply(0x09, temp[3]);
            state[1][j] = GaloisMultiply(0x09, temp[0]) ^ GaloisMultiply(0x0e, temp[1]) ^ 
                          GaloisMultiply(0x0b, temp[2]) ^ GaloisMultiply(0x0d, temp[3]);
            state[2][j] = GaloisMultiply(0x0d, temp[0]) ^ GaloisMultiply(0x09, temp[1]) ^ 
                          GaloisMultiply(0x0e, temp[2]) ^ GaloisMultiply(0x0b, temp[3]);
            state[3][j] = GaloisMultiply(0x0b, temp[0]) ^ GaloisMultiply(0x0d, temp[1]) ^ 
                          GaloisMultiply(0x09, temp[2]) ^ GaloisMultiply(0x0e, temp[3]);
        }
    }

    // Thuật toán mã hóa AES
    void Cipher(byte* input, byte* output, const byte* expanded_key) {
        state_t state;
        
        // Sao chép input vào state (theo cột)
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = input[i * 4 + j];
            }
        }
        
        // Vòng ban đầu
        AddRoundKey(state, expanded_key);
        
        // Các vòng chính
        for (int round = 1; round < Nr; round++) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, expanded_key + round * 4 * Nb);
        }
        
        // Vòng cuối (không có MixColumns)
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, expanded_key + Nr * 4 * Nb);
        
        // Sao chép state vào output (theo cột)
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i * 4 + j] = state[j][i];
            }
        }
    }

    // Thuật toán giải mã AES
    void InvCipher(byte* input, byte* output, const byte* expanded_key) {
        state_t state;
        
        // Sao chép input vào state (theo cột)
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = input[i * 4 + j];
            }
        }
        
        // Vòng ban đầu
        AddRoundKey(state, expanded_key + Nr * 4 * Nb);
        
        // Các vòng chính
        for (int round = Nr - 1; round > 0; round--) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, expanded_key + round * 4 * Nb);
            InvMixColumns(state);
        }
        
        // Vòng cuối (không có InvMixColumns)
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, expanded_key);
        
        // Sao chép state vào output (theo cột)
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i * 4 + j] = state[j][i];
            }
        }
    }

    // Hàm mã hóa file
    void EncryptFile(const std::string& input_file, const std::string& output_file, const byte* key) {
        // Mở file đầu vào để đọc ở chế độ nhị phân
        std::ifstream in(input_file, std::ios::binary);
        if (!in) {
            std::cerr << "Không thể mở file đầu vào: " << input_file << std::endl;
            return;
        }
        
        // Mở file đầu ra để ghi ở chế độ nhị phân
        std::ofstream out(output_file, std::ios::binary);
        if (!out) {
            std::cerr << "Không thể mở file đầu ra: " << output_file << std::endl;
            in.close();
            return;
        }
        
        // Tạo khóa mở rộng
        byte expanded_key[4 * Nb * (Nr + 1)];
        KeyExpansion(key, expanded_key);
        
        // Đọc và mã hóa từng khối 16-byte
        byte in_block[AES_BLOCK_SIZE];
        byte out_block[AES_BLOCK_SIZE];
        
        while (in) {
            // Đọc một khối
            in.read(reinterpret_cast<char*>(in_block), AES_BLOCK_SIZE);
            int bytes_read = in.gcount();
            
            if (bytes_read == 0) {
                break; // Hết file
            }
            
            // Nếu khối không đủ 16 byte thì thêm padding
            if (bytes_read < AES_BLOCK_SIZE) {
                // Thêm padding PKCS#7: thêm giá trị bằng số byte cần thêm
                byte padding_value = AES_BLOCK_SIZE - bytes_read;
                for (int i = bytes_read; i < AES_BLOCK_SIZE; i++) {
                    in_block[i] = padding_value;
                }
            }
            
            // Mã hóa khối
            Cipher(in_block, out_block, expanded_key);
            
            // Ghi khối đã mã hóa vào file
            out.write(reinterpret_cast<char*>(out_block), AES_BLOCK_SIZE);
        }
        
    }

    // Hàm giải mã file
    void DecryptFile(const std::string& input_file, const std::string& output_file, const byte* key) {
        // Mở file đầu vào để đọc ở chế độ nhị phân
        std::ifstream in(input_file, std::ios::binary);
        if (!in) {
            std::cerr << "Không thể mở file đầu vào: " << input_file << std::endl;
            return;
        }
        
        // Mở file đầu ra để ghi ở chế độ nhị phân
        std::ofstream out(output_file, std::ios::binary);
        if (!out) {
            std::cerr << "Không thể mở file đầu ra: " << output_file << std::endl;
            in.close();
            return;
        }
        
        // Tạo khóa mở rộng
        byte expanded_key[4 * Nb * (Nr + 1)];
        KeyExpansion(key, expanded_key);
        
        // Đọc và giải mã từng khối 16-byte
        byte in_block[AES_BLOCK_SIZE];
        byte out_block[AES_BLOCK_SIZE];
        std::vector<byte> decrypted_data;
        
        while (in) {
            // Đọc một khối đã mã hóa
            in.read(reinterpret_cast<char*>(in_block), AES_BLOCK_SIZE);
            int bytes_read = in.gcount();
            
            if (bytes_read == 0) {
                break; // Hết file
            }
            
            if (bytes_read != AES_BLOCK_SIZE) {
                std::cerr << "Dữ liệu mã hóa không hợp lệ: kích thước khối không đúng." << std::endl;
                in.close();
                out.close();
                return;
            }
            
            // Giải mã khối
            InvCipher(in_block, out_block, expanded_key);
            
            // Lưu khối đã giải mã
            for (int i = 0; i < AES_BLOCK_SIZE; i++) {
                decrypted_data.push_back(out_block[i]);
            }
        }
        
        // Kiểm tra và xử lý padding
        if (!decrypted_data.empty()) {
            byte padding_value = decrypted_data.back();
            if (padding_value > 0 && padding_value <= AES_BLOCK_SIZE) {
                // Kiểm tra tính hợp lệ của padding
                bool valid_padding = true;
                for (int i = 0; i < padding_value; i++) {
                    if (decrypted_data[decrypted_data.size() - 1 - i] != padding_value) {
                        valid_padding = false;
                        break;
                    }
                }
                
                // Nếu padding hợp lệ, loại bỏ padding
                if (valid_padding) {
                    decrypted_data.resize(decrypted_data.size() - padding_value);
                }
            }
        }
        // Ghi dữ liệu đã giải mã vào file đầu ra
    out.write(reinterpret_cast<char*>(decrypted_data.data()), decrypted_data.size());
}
}

    // Hàm in dữ liệu dưới dạng hex
    void PrintHex(const byte* data, int len) {
        for (int i = 0; i < len; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
        }
        std::cout << std::dec << std::endl;
    }

    // Hàm in trạng thái
    void PrintState(const state_t& state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)state[i][j] << " ";
            }
            std::cout << std::dec << std::endl;
        }
    }