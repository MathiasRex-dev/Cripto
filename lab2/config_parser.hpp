#pragma once

#include "cipher_engine.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include <vector>

class Base64 {
    static inline const std::string b64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

public:
    static std::vector<uint8_t> decode(const std::string& in) {
        std::vector<uint8_t> out;
        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) T[b64_chars[i]] = i;

        int val = 0, valb = -8;
        for (unsigned char c : in) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                out.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }
};

struct ConfigParser {
    static CipherModule create_module_from_json(const std::string& json_path) {
        std::ifstream f(json_path);
        if (!f.is_open()) throw std::runtime_error("Could not open config JSON: " + json_path);

        nlohmann::json j;
        f >> j;

        size_t blocksize = j.at("blocksize").get<size_t>();
        std::string cipher_name = j.at("cipher").get<std::string>();
        std::string key_b64 = j.at("key").get<std::string>();
        std::string mode_str = j.at("mode").get<std::string>();
        std::string pad_str = j.at("padding").get<std::string>();

        std::vector<uint8_t> key = Base64::decode(key_b64);

        Mode mode;
        if (mode_str == "ECB") mode = Mode::ECB;
        else if (mode_str == "CBC") mode = Mode::CBC;
        else if (mode_str == "CFB") mode = Mode::CFB;
        else if (mode_str == "OFB") mode = Mode::OFB;
        else if (mode_str == "CTR") mode = Mode::CTR;
        else throw std::invalid_argument("Unknown mode: " + mode_str);

        Padding padding;
        if (pad_str == "ZERO") padding = Padding::ZERO;
        else if (pad_str == "DES") padding = Padding::DES;
        else if (pad_str == "SF") padding = Padding::SF;
        else throw std::invalid_argument("Unknown padding: " + pad_str);

        std::vector<uint8_t> iv;
        if (mode != Mode::ECB) {
            if (!j.contains("iv")) throw std::invalid_argument("IV required for non-ECB mode");
            iv = Base64::decode(j.at("iv").get<std::string>());
        }

        std::shared_ptr<IBlockCipher> cipher;
        if (cipher_name == "VIGENERE-BIN") {
            cipher = std::make_shared<BinaryVigenereCipher>(blocksize, key);
        } else {
#ifdef WITH_OPENSSL
            cipher = std::make_shared<OpenSSLCipher>(cipher_name, key);
#else
            throw std::runtime_error("OpenSSL ciphers not compiled into binary");
#endif
        }

        return CipherModule(cipher, mode, padding, iv);
    }
};
