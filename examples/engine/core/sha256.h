// SHA-256 (FIPS 180-4). Small self-contained implementation so the runtime needs no crypto library.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace apg {

class Sha256 {
public:
    Sha256();
    void update(const void* data, size_t len);
    // Finish and return the lower-case hex digest (64 characters). The object must not be reused.
    std::string hex_final();

private:
    void transform(const uint8_t block[64]);
    uint32_t state_[8];
    uint64_t total_bytes_;
    uint8_t buffer_[64];
    size_t buffer_len_;
};

std::string sha256_hex(const void* data, size_t len);
std::string sha256_hex(const std::string& s);
// Streams the file; returns false and fills *error when it cannot be read.
bool sha256_file(const std::string& path_utf8, std::string* hex, std::string* error);

}  // namespace apg
