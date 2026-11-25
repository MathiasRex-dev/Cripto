#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include "config_parser.hpp"

#ifdef WITH_OPENSSL
#include <openssl/provider.h>
#endif

namespace {

#ifdef WITH_OPENSSL
struct OpenSSLProviderGuard {
  OSSL_PROVIDER* default_provider = nullptr;
  OSSL_PROVIDER* legacy_provider = nullptr;

  OpenSSLProviderGuard() {
    default_provider = OSSL_PROVIDER_load(nullptr, "default");
    legacy_provider = OSSL_PROVIDER_load(nullptr, "legacy");
  }

  ~OpenSSLProviderGuard() {
    if (legacy_provider) {
      OSSL_PROVIDER_unload(legacy_provider);
    }
    if (default_provider) {
      OSSL_PROVIDER_unload(default_provider);
    }
  }
};
#endif

std::vector<std::uint8_t> read_file(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    throw std::runtime_error("Nem nyithato meg a bemeneti fajl: " + path);
  }
  return std::vector<std::uint8_t>(
      std::istreambuf_iterator<char>(file),
      std::istreambuf_iterator<char>()
  );
}

void write_file(const std::string& path, const std::vector<std::uint8_t>& data) {
  std::ofstream file(path, std::ios::binary);
  if (!file.is_open()) {
    throw std::runtime_error("Nem irhato a kimeneti fajl: " + path);
  }
  file.write(
      reinterpret_cast<const char*>(data.data()),
      static_cast<std::streamsize>(data.size())
  );
}

}

int main(int argc, char* argv[]) {
  if (argc != 5) {
    std::cerr << "Hasznalat: " << argv[0] << " <encrypt|decrypt> <config.json> <bemenet> <kimenet>\n";
    return 1;
  }

  const std::string operation = argv[1];
  const std::string config_path = argv[2];
  const std::string input_path = argv[3];
  const std::string output_path = argv[4];

  try {
#ifdef WITH_OPENSSL
    OpenSSLProviderGuard provider_guard;
#endif

    CipherModule module = ConfigParser::create_module_from_json(config_path);
    std::vector<std::uint8_t> input_data = read_file(input_path);
    std::vector<std::uint8_t> output_data;

    if (operation == "encrypt") {
      output_data = module.encrypt(input_data);
    } else if (operation == "decrypt") {
      output_data = module.decrypt(input_data);
    } else {
      throw std::invalid_argument("Ismeretlen muvelet (csak encrypt vagy decrypt): " + operation);
    }

    write_file(output_path, output_data);
  } catch (const std::exception& ex) {
    std::cerr << "Hiba: " << ex.what() << '\n';
    return 1;
  }

  return 0;
}
