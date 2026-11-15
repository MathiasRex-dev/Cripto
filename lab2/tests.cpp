#include <gtest/gtest.h>
#include "cipher_engine.hpp"
#include <random>

class CipherTest : public ::testing::TestWithParam<std::tuple<std::string, Mode, Padding>> {};

TEST_P(CipherTest, LargeDataEncryptDecrypt) {
    auto [cipher_name, mode, padding] = GetParam();

    // 1 MB + 123 byte teszt bináris állomány generálása
    const size_t data_size = 1024 * 1024 + 123;
    std::vector<uint8_t> original_data(data_size);
    std::mt19937 rng(42);
    for (size_t i = 0; i < data_size; ++i) {
        original_data[i] = static_cast<uint8_t>(rng() % 256);
    }

    size_t block_size = (cipher_name == "AES-256") ? 16 : 8;
    std::vector<uint8_t> key(32, 0x42);
    std::vector<uint8_t> iv(block_size, 0x1A);

    std::shared_ptr<IBlockCipher> cipher;
    if (cipher_name == "VIGENERE-BIN") {
        cipher = std::make_shared<BinaryVigenereCipher>(block_size, key);
    } else {
#ifdef WITH_OPENSSL
        cipher = std::make_shared<OpenSSLCipher>(cipher_name, key);
#endif
    }

    if (!cipher) return; 

    CipherModule module(cipher, mode, padding, iv);

    std::vector<uint8_t> encrypted = module.encrypt(original_data);
    EXPECT_NE(original_data, encrypted);

    std::vector<uint8_t> decrypted = module.decrypt(encrypted);
    
    if (padding != Padding::ZERO) {
        EXPECT_EQ(original_data.size(), decrypted.size());
        EXPECT_EQ(original_data, decrypted);
    } else {
        EXPECT_GE(decrypted.size(), original_data.size());
        EXPECT_EQ(0, memcmp(original_data.data(), decrypted.data(), original_data.size()));
    }
}

INSTANTIATE_TEST_SUITE_P(
    AllCipherCombinations,
    CipherTest,
    ::testing::Combine(
        ::testing::Values("VIGENERE-BIN"
#ifdef WITH_OPENSSL
        , "AES-256"
#endif
        ),
        ::testing::Values(Mode::ECB, Mode::CBC, Mode::CFB, Mode::OFB, Mode::CTR),
        ::testing::Values(Padding::ZERO, Padding::DES, Padding::SF)
    )
);
