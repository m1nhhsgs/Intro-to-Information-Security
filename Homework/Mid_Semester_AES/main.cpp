#include "AES.hpp"
#include <filesystem>

int main(int argc, char* argv[]) {
    // Thư mục đầu ra cho các file input/output
    std::string output_folder = "aes_data";
    
    // Tạo thư mục nếu chưa tồn tại
    if (!std::filesystem::exists(output_folder)) {
        std::filesystem::create_directory(output_folder);
    }
    
    // Đường dẫn file
    std::string plaintext_file = output_folder + "/plaintext.txt";
    std::string encrypted_file = output_folder + "/encrypted.txt";
    std::string decrypted_file = output_folder + "/decrypted.txt";
    
    // Tạo file plaintext với nội dung mẫu
    {
        std::ofstream plain_out(plaintext_file);
        if (plain_out) {
            plain_out << "Đây là một ví dụ về dữ liệu được mã hóa và giải mã bằng thuật toán AES.\n";
            plain_out << "AES (Advanced Encryption Standard) là một thuật toán mã hóa khối được sử dụng rộng rãi.\n";
            plain_out << "Thuật toán này được thiết kế bởi Vincent Rijmen và Joan Daemen.\n";
            plain_out.close();
            std::cout << "Đã tạo file plaintext tại: " << plaintext_file << std::endl;
        } else {
            std::cerr << "Không thể tạo file plaintext!\n";
            return 1;
        }
    }
    
    // Khóa mã hóa
    byte key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    std::cout << "Khóa mã hóa: ";
    AES::PrintHex(key, 16);
    
    // Mã hóa file
    std::cout << "Đang mã hóa file...\n";
    AES::EncryptFile(plaintext_file, encrypted_file, key);
    std::cout << "Mã hóa hoàn tất. File mã hóa được lưu tại: " << encrypted_file << std::endl;
    
    // Giải mã file
    std::cout << "Đang giải mã file...\n";
    AES::DecryptFile(encrypted_file, decrypted_file, key);
    std::cout << "Giải mã hoàn tất. File giải mã được lưu tại: " << decrypted_file << std::endl;
    
    // So sánh nội dung file plaintext và decrypted
    std::ifstream plain_in(plaintext_file, std::ios::binary);
    std::ifstream decrypted_in(decrypted_file, std::ios::binary);
    
    if (!plain_in || !decrypted_in) {
        std::cerr << "Không thể mở file để so sánh!\n";
        return 1;
    }
    
    std::string plain_content((std::istreambuf_iterator<char>(plain_in)), std::istreambuf_iterator<char>());
    std::string decrypted_content((std::istreambuf_iterator<char>(decrypted_in)), std::istreambuf_iterator<char>());
    
    plain_in.close();
    decrypted_in.close();
    
    if (plain_content == decrypted_content) {
        std::cout << "Kiểm tra thành công: Nội dung file plaintext và file được giải mã giống nhau.\n";
    } else {
        std::cout << "Kiểm tra thất bại: Nội dung file plaintext và file được giải mã khác nhau!\n";
    }
    
    return 0;
}