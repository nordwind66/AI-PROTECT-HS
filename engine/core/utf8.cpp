#include "utf8.h"

namespace apg {

bool utf8_valid(const uint8_t* p, size_t n, size_t* bad_offset) {
    size_t i = 0;
    while (i < n) {
        const uint8_t c = p[i];
        if (c < 0x80) {
            ++i;
            continue;
        }
        size_t len;
        uint32_t cp;
        if (c >= 0xC2 && c <= 0xDF) {
            len = 2;
            cp = c & 0x1Fu;
        } else if (c >= 0xE0 && c <= 0xEF) {
            len = 3;
            cp = c & 0x0Fu;
        } else if (c >= 0xF0 && c <= 0xF4) {
            len = 4;
            cp = c & 0x07u;
        } else {
            if (bad_offset) *bad_offset = i;
            return false;
        }
        if (i + len > n) {
            if (bad_offset) *bad_offset = i;
            return false;
        }
        for (size_t k = 1; k < len; ++k) {
            const uint8_t cc = p[i + k];
            if ((cc & 0xC0u) != 0x80u) {
                if (bad_offset) *bad_offset = i;
                return false;
            }
            cp = (cp << 6) | (cc & 0x3Fu);
        }
        const bool overlong = (len == 3 && cp < 0x800u) || (len == 4 && cp < 0x10000u);
        const bool surrogate = cp >= 0xD800u && cp <= 0xDFFFu;
        if (overlong || surrogate || cp > 0x10FFFFu) {
            if (bad_offset) *bad_offset = i;
            return false;
        }
        i += len;
    }
    return true;
}

size_t utf8_decode(const uint8_t* p, size_t n, uint32_t* cp) {
    const uint8_t c = p[0];
    if (c < 0x80) {
        *cp = c;
        return 1;
    }
    if (c < 0xE0 && n >= 2) {
        *cp = ((c & 0x1Fu) << 6) | (p[1] & 0x3Fu);
        return 2;
    }
    if (c < 0xF0 && n >= 3) {
        *cp = ((c & 0x0Fu) << 12) | ((p[1] & 0x3Fu) << 6) | (p[2] & 0x3Fu);
        return 3;
    }
    if (n >= 4) {
        *cp = ((c & 0x07u) << 18) | ((p[1] & 0x3Fu) << 12) | ((p[2] & 0x3Fu) << 6) | (p[3] & 0x3Fu);
        return 4;
    }
    *cp = 0xFFFDu;  // truncated input (cannot happen for validated text)
    return 1;
}

void utf8_append(std::string& out, uint32_t cp) {
    if (cp < 0x80u) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800u) {
        out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else if (cp < 0x10000u) {
        out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else {
        out.push_back(static_cast<char>(0xF0u | (cp >> 18)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    }
}

}  // namespace apg
