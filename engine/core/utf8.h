// Strict UTF-8 helpers (RFC 3629): no overlong forms, no surrogates, nothing above U+10FFFF.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace apg {

// Returns true if [p, p+n) is well-formed UTF-8. On failure *bad_offset (if given) receives the byte offset of
// the first offending sequence. Embedded NUL bytes (U+0000) are valid.
bool utf8_valid(const uint8_t* p, size_t n, size_t* bad_offset = nullptr);

// Decodes one code point from VALID UTF-8 (the caller validated the buffer). Returns the number of bytes
// consumed (1-4). At least one byte must be available.
size_t utf8_decode(const uint8_t* p, size_t n, uint32_t* cp);

// Appends the UTF-8 encoding of cp (cp must be a valid scalar value).
void utf8_append(std::string& out, uint32_t cp);

// Number of bytes needed to encode cp.
inline size_t utf8_length(uint32_t cp) { return cp < 0x80u ? 1 : cp < 0x800u ? 2 : cp < 0x10000u ? 3 : 4; }

}  // namespace apg
