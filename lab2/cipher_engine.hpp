#pragma once

#include <cstddef>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <cstdint>
#include <stdexcept>
#include <algorithm>

enum class Mode { ECB, CBC, CFB, OFB, CTR };
enum class Padding { ZERO, DES, SF };

class IBlockCipher {
public:
    virtual ~IBlockCipher() = default;
    virtual size_t block_size() const = 0;
    virtual void encrypt_block(const uint8_t* in, uint8_t* out) = 0;
    virtual void decrypt_block(const uint8_t* in, uint8_t* out) = 0;
};

class BinaryVigenereCipher : public IBlockCipher {
    size_t b_size;
    std::vector<uint8_t> key;

    uint8_t rotl(uint8_t val, int shift) const {
        return (val << shift) | (val >> (8 - shift));
    }
    uint8_t rotr(uint8_t val, int shift) const {
        return (val >> shift) | (val << (8 - shift));
    }

public:
    BinaryVigenereCipher(size_t block_size, std::vector<uint8_t> key_material)
        : b_size(block_size), key(std::move(key_material)) {
        if (key.empty()) throw std::invalid_argument("Key cannot be empty");
    }

    size_t block_size() const override { return b_size; }

    void encrypt_block(const uint8_t* in, uint8_t* out) override {
        for (size_t i = 0; i < b_size; ++i) {
            uint8_t k = key[i % key.size()];
            uint8_t p = in[i] ^ k;
            out[i] = rotl(p, (k % 7) + 1);
        }
    }

    void decrypt_block(const uint8_t* in, uint8_t* out) override {
        for (size_t i = 0; i < b_size; ++i) {
            uint8_t k = key[i % key.size()];
            uint8_t p = rotr(in[i], (k % 7) + 1);
            out[i] = p ^ k;
        }
    }
};

#ifdef WITH_OPENSSL
#include <openssl/evp.h>

class OpenSSLCipher : public IBlockCipher {
    const EVP_CIPHER* evp_cipher;
    std::vector<uint8_t> key;
    size_t b_size;

public:
    OpenSSLCipher(const std::string& name, std::vector<uint8_t> key_mat) 
        : key(std::move(key_mat)) {
        if (name == "AES-128") evp_cipher = EVP_aes_128_ecb();
        else if (name == "AES-192") evp_cipher = EVP_aes_192_ecb();
        else if (name == "AES-256") evp_cipher = EVP_aes_256_ecb();
        else if (name == "DES") evp_cipher = EVP_des_ecb();
        else if (name == "3DES") evp_cipher = EVP_des_ede3_ecb();
        else throw std::invalid_argument("Unsupported OpenSSL cipher: " + name);

        b_size = EVP_CIPHER_block_size(evp_cipher);
        if (key.size() < static_cast<size_t>(EVP_CIPHER_key_length(evp_cipher))) {
            throw std::invalid_argument("Key length insufficient for cipher " + name);
        }
    }

    size_t block_size() const override { return b_size; }

    void encrypt_block(const uint8_t* in, uint8_t* out) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, evp_cipher, nullptr, key.data(), nullptr);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        EVP
        int outlen = 0;
        EVP_EncryptUpdate(ctx, out, &outlen, in, static_cast<int>(b_size));
        EVP_CIPHER_CTX_free(ctx);
    }

    void decrypt_block(const uint8_t* in, uint8_t* out) override {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, evp_cipher, nullptr, key.data(), nullptr);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outlen = 0;
        EVP_DecryptUpdate(ctx, out, &outlen, in, static_cast<int>(b_size));
        EVP_CIPHER_CTX_free(ctx);
    }
};
#endif

class CipherModule {
    std::shared_ptr<IBlockCipher> cipher;
    Mode mode;
    Padding padding;
    std::vector<uint8_t> iv;

    void increment_counter(std::vector<uint8_t>& ctr) const {
        for (int i = static_cast<int>(ctr.size()) - 1; i >= 0; --i) {
            if (++ctr[i] != 0) break;
        }
    }

public:
    CipherModule(std::shared_ptr<IBlockCipher> cipher, Mode mode, Padding padding, std::vector<uint8_t> iv = {})
        : cipher(std::move(cipher)), mode(mode), padding(padding), iv(std::move(iv)) {
        size_t bs = this->cipher->block_size();
        if (mode != Mode::ECB && this->iv.size() != bs) {
            throw std::invalid_argument("IV size must match cipher block size");
        }
    }

    std::vector<uint8_t> add_padding(const std::vector<uint8_t>& data) const {
        size_t bs = cipher->block_size();
        std::vector<uint8_t> padded = data;
        size_t rem = data.size() % bs;

        if (padding == Padding::ZERO) {
            if (rem != 0) {
                padded.resize(data.size() + (bs - rem), 0x00);
            }
        } else if (padding == Padding::DES) {
            padded.push_back(0x80);
            while (padded.size() % bs != 0) {
                padded.push_back(0x00);
            }
        } else if (padding == Padding::SF) {
            uint8_t pad_val = static_cast<uint8_t>(bs - rem);
            padded.insert(padded.end(), pad_val, pad_val);
        }
        return padded;
    }

    std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& data) const {
        if (data.empty()) return {};
        size_t bs = cipher->block_size();

        if (padding == Padding::ZERO) {
            size_t end = data.size();
            while (end > 0 && data[end - 1] == 0x00) {
                --end;
            }
            return std::vector<uint8_t>(data.begin(), data.begin() + end);
        } else if (padding == Padding::DES) {
            ssize_t idx = static_cast<ssize_t>(data.size()) - 1;
            while (idx >= 0 && data[idx] == 0x00) {
                --idx;
            }
            if (idx >= 0 && data[idx] == 0x80) {
                return std::vector<uint8_t>(data.begin(), data.begin() + idx);
            }
            return data;
        } else if (padding == Padding::SF) {
            uint8_t pad_val = data.back();
            if (pad_val > 0 && pad_val <= bs && data.size() >= pad_val) {
                return std::vector<uint8_t>(data.begin(), data.end() - pad_val);
            }
            return data;
        }
        return data;
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& input) const {
        std::vector<uint8_t> data = add_padding(input);
        size_t bs = cipher->block_size();
        size_t num_blocks = data.size() / bs;
        std::vector<uint8_t> output(data.size());

        if (mode == Mode::ECB) {
            for (size_t i = 0; i < num_blocks; ++i) {
                cipher->encrypt_block(&data[i * bs], &output[i * bs]);
            }
        } else if (mode == Mode::CBC) {
            std::vector<uint8_t> prev = iv;
            for (size_t i = 0; i < num_blocks; ++i) {
                std::vector<uint8_t> block(bs);
                for (size_t j = 0; j < bs; ++j) block[j] = data[i * bs + j] ^ prev[j];
                cipher->encrypt_block(block.data(), &output[i * bs]);
                std::copy(output.begin() + i * bs, output.begin() + (i + 1) * bs, prev.begin());
            }
        } else if (mode == Mode::CFB) {
            std::vector<uint8_t> shift_reg = iv;
            std::vector<uint8_t> enc_reg(bs);
            for (size_t i = 0; i < num_blocks; ++i) {
                cipher->encrypt_block(shift_reg.data(), enc_reg.data());
                for (size_t j = 0; j < bs; ++j) {
                    output[i * bs + j] = data[i * bs + j] ^ enc_reg[j];
                }
                std::copy(output.begin() + i * bs, output.begin() + (i + 1) * bs, shift_reg.begin());
            }
        } else if (mode == Mode::OFB) {
            std::vector<uint8_t> shift_reg = iv;
            for (size_t i = 0; i < num_blocks; ++i) {
                cipher->encrypt_block(shift_reg.data(), shift_reg.data());
                for (size_t j = 0; j < bs; ++j) {
                    output[i * bs + j] = data[i * bs + j] ^ shift_reg[j];
                }
            }
        } else if (mode == Mode::CTR) {
            std::vector<uint8_t> ctr = iv;
            std::vector<uint8_t> keystream(bs);
            for (size_t i = 0; i < num_blocks; ++i) {
                cipher->encrypt_block(ctr.data(), keystream.data());
                for (size_t j = 0; j < bs; ++j) {
                    output[i * bs + j] = data[i * bs + j] ^ keystream[j];
                }
                increment_counter(ctr);
            }
        }
        return output;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& input) const {
        size_t bs = cipher->block_size();
        if (input.size() % bs != 0) {
            throw std::invalid_argument("Input data length is not a multiple of block size");
        }
        size_t num_blocks = input.size() / bs;
        std::vector<uint8_t> output(input.size());

        if (mode == Mode::ECB) {
            for (size_t i = 0; i < num_blocks; ++i) {
                cipher->decrypt_block(&input[i * bs], &output[i * bs]);
            }
        } else if (mode == Mode::CBC) {
            std::vector<uint8_t> prev = iv;
            for (size_t i = 0; i < num_blocks; ++i) {
                std::vector<uint8_t> dec_block(bs);
                cipher->decrypt_block(&input[i * bs], dec_block.data());
                for (size_t j = 0; j < bs; ++j) {
                    output[i * bs + j] = dec_block[j] ^ prev[j];
                }
                std::copy(input.begin() + i * bs, input.begin() + (i + 1) * bs, prev.begin());
            }
        } else if (mode == Mode::CFB) {
            std::vector<uint8_t> shift_reg = iv;
            std::vector<uint8_t> enc_reg(bs);
            for (size_t i = 0; i < num_blocks; ++i) {
                cipher->encrypt_block(shift_reg.data(), enc_reg.data());
                for (size_t j = 0; j < bs; ++j) {
                    output[i * bs + j] = input[i * bs + j] ^ enc_reg[j];
                }
                std::copy(input.begin() + i * bs, input.begin() + (i + 1) * bs, shift_reg.begin());
            }
        } else if (mode == Mode::OFB) {
            std::vector<uint8_t> shift_reg = iv;
            for (size_t i = 0; i < num_blocks; ++i) {
                cipher->encrypt_block(shift_reg.data(), shift_reg.data());
                for (size_t j = 0; j < bs; ++j) {
                    output[i * bs + j] = input[i * bs + j] ^ shift_reg[j];
                }
            }
        } else if (mode == Mode::CTR) {
            std::vector<uint8_t> ctr = iv;
            std::vector<uint8_t> keystream(bs);
            for (size_t i = 0; i < num_blocks; ++i) {
                cipher->encrypt_block(ctr.data(), keystream.data());
                for (size_t j = 0; j < bs; ++j) {
                    output[i * bs + j] = input[i * bs + j] ^ keystream[j];
                }
                increment_counter(ctr);
            }
        }
        return remove_padding(output);
    }
};
