#include "json.h"

#include <algorithm>
#include <cmath>
#include <cstring>

#include "utf8.h"

namespace apg {

// ------------------------------------------------------------------------------------------------
// accessors
// ------------------------------------------------------------------------------------------------
namespace {
[[noreturn]] void type_error(const char* want) {
    throw Error(Status::InvalidArgument, std::string("JSON value is not ") + want);
}
}  // namespace

bool Json::as_bool() const {
    if (type_ != Type::Bool) type_error("a boolean");
    return b_;
}
int64_t Json::as_int() const {
    if (type_ != Type::Int) type_error("an integer");
    return i_;
}
double Json::as_double() const {
    if (type_ == Type::Int) return static_cast<double>(i_);
    if (type_ != Type::Double) type_error("a number");
    return d_;
}
const std::string& Json::as_string() const {
    if (type_ != Type::String) type_error("a string");
    return s_;
}
const std::vector<Json>& Json::items() const {
    if (type_ != Type::Array) type_error("an array");
    return arr_;
}
const std::vector<std::pair<std::string, Json>>& Json::members() const {
    if (type_ != Type::Object) type_error("an object");
    return obj_;
}
const Json* Json::get(const std::string& key) const {
    if (type_ != Type::Object) return nullptr;
    for (const auto& kv : obj_) {
        if (kv.first == key) return &kv.second;
    }
    return nullptr;
}

// ------------------------------------------------------------------------------------------------
// parser
// ------------------------------------------------------------------------------------------------
namespace {

class Parser {
public:
    Parser(const char* data, size_t len, size_t max_depth) : p_(data), end_(data + len), begin_(data), max_depth_(max_depth) {}

    Json parse_document() {
        skip_ws();
        Json v = parse_value(0);
        skip_ws();
        if (p_ != end_) fail("unexpected data after the JSON document");
        return v;
    }

private:
    [[noreturn]] void fail(const std::string& msg) const {
        throw Error(Status::InvalidArgument, "invalid JSON at byte " + std::to_string(p_ - begin_) + ": " + msg);
    }
    void skip_ws() {
        while (p_ < end_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\n' || *p_ == '\r')) ++p_;
    }
    bool match(const char* lit) {
        const size_t n = std::strlen(lit);
        if (static_cast<size_t>(end_ - p_) >= n && std::memcmp(p_, lit, n) == 0) {
            p_ += n;
            return true;
        }
        return false;
    }

    Json parse_value(size_t depth) {
        if (depth > max_depth_) fail("nesting too deep");
        if (p_ >= end_) fail("unexpected end of input");
        const char c = *p_;
        if (c == '{') return parse_object(depth);
        if (c == '[') return parse_array(depth);
        if (c == '"') return Json::make_string(parse_string());
        if (c == 't') {
            if (match("true")) return Json::make_bool(true);
            fail("bad literal");
        }
        if (c == 'f') {
            if (match("false")) return Json::make_bool(false);
            fail("bad literal");
        }
        if (c == 'n') {
            if (match("null")) return Json();
            fail("bad literal");
        }
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
        fail("unexpected character");
    }

    Json parse_object(size_t depth) {
        ++p_;  // '{'
        Json obj = Json::make_object();
        skip_ws();
        if (p_ < end_ && *p_ == '}') {
            ++p_;
            return obj;
        }
        for (;;) {
            skip_ws();
            if (p_ >= end_ || *p_ != '"') fail("object key must be a string");
            std::string key = parse_string();
            if (obj.get(key) != nullptr) fail("duplicate object key '" + key + "'");
            skip_ws();
            if (p_ >= end_ || *p_ != ':') fail("expected ':' after object key");
            ++p_;
            skip_ws();
            obj.set(key, parse_value(depth + 1));
            skip_ws();
            if (p_ >= end_) fail("unterminated object");
            if (*p_ == ',') {
                ++p_;
                continue;
            }
            if (*p_ == '}') {
                ++p_;
                return obj;
            }
            fail("expected ',' or '}' in object");
        }
    }

    Json parse_array(size_t depth) {
        ++p_;  // '['
        Json arr = Json::make_array();
        skip_ws();
        if (p_ < end_ && *p_ == ']') {
            ++p_;
            return arr;
        }
        for (;;) {
            skip_ws();
            arr.push_back(parse_value(depth + 1));
            skip_ws();
            if (p_ >= end_) fail("unterminated array");
            if (*p_ == ',') {
                ++p_;
                continue;
            }
            if (*p_ == ']') {
                ++p_;
                return arr;
            }
            fail("expected ',' or ']' in array");
        }
    }

    static int hex_val(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    uint32_t parse_hex4() {
        if (end_ - p_ < 4) fail("truncated \\u escape");
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            const int h = hex_val(p_[i]);
            if (h < 0) fail("bad \\u escape");
            v = (v << 4) | static_cast<uint32_t>(h);
        }
        p_ += 4;
        return v;
    }

    std::string parse_string() {
        ++p_;  // opening quote
        std::string out;
        for (;;) {
            if (p_ >= end_) fail("unterminated string");
            const unsigned char c = static_cast<unsigned char>(*p_);
            if (c == '"') {
                ++p_;
                return out;
            }
            if (c < 0x20) fail("control character in string");
            if (c != '\\') {
                out.push_back(static_cast<char>(c));
                ++p_;
                continue;
            }
            ++p_;  // backslash
            if (p_ >= end_) fail("truncated escape");
            const char e = *p_++;
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    uint32_t cp = parse_hex4();
                    if (cp >= 0xD800u && cp <= 0xDBFFu) {
                        if (end_ - p_ >= 6 && p_[0] == '\\' && p_[1] == 'u') {
                            p_ += 2;
                            const uint32_t lo = parse_hex4();
                            if (lo < 0xDC00u || lo > 0xDFFFu) fail("invalid low surrogate");
                            cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                        } else {
                            fail("lone high surrogate");
                        }
                    } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
                        fail("lone low surrogate");
                    }
                    utf8_append(out, cp);
                    break;
                }
                default: fail("unknown escape sequence");
            }
        }
    }

    static double pow10_exact(int k) {
        double r = 1.0;
        for (int i = 0; i < k; ++i) r *= 10.0;
        return r;
    }

    Json parse_number() {
        const char* start = p_;
        bool neg = false;
        if (*p_ == '-') {
            neg = true;
            ++p_;
        }
        if (p_ >= end_) fail("bad number");
        uint64_t mant = 0;
        int mant_digits = 0;
        int exp10 = 0;      // exponent adjustment from dropped / fractional digits
        bool is_integer = true;
        if (*p_ == '0') {
            ++p_;
            if (p_ < end_ && *p_ >= '0' && *p_ <= '9') fail("leading zeros are not allowed");
        } else if (*p_ >= '1' && *p_ <= '9') {
            while (p_ < end_ && *p_ >= '0' && *p_ <= '9') {
                add_digit(*p_, &mant, &mant_digits, &exp10, false);
                ++p_;
            }
        } else {
            fail("bad number");
        }
        if (p_ < end_ && *p_ == '.') {
            is_integer = false;
            ++p_;
            if (p_ >= end_ || *p_ < '0' || *p_ > '9') fail("digits expected after '.'");
            while (p_ < end_ && *p_ >= '0' && *p_ <= '9') {
                add_digit(*p_, &mant, &mant_digits, &exp10, true);
                ++p_;
            }
        }
        if (p_ < end_ && (*p_ == 'e' || *p_ == 'E')) {
            is_integer = false;
            ++p_;
            bool eneg = false;
            if (p_ < end_ && (*p_ == '+' || *p_ == '-')) {
                eneg = (*p_ == '-');
                ++p_;
            }
            if (p_ >= end_ || *p_ < '0' || *p_ > '9') fail("digits expected in exponent");
            int e = 0;
            while (p_ < end_ && *p_ >= '0' && *p_ <= '9') {
                if (e < 10000) e = e * 10 + (*p_ - '0');
                ++p_;
            }
            exp10 += eneg ? -e : e;
        }
        (void)start;
        if (is_integer && exp10 == 0 && mant_digits <= 18) {
            const int64_t v = static_cast<int64_t>(mant);
            return Json::make_int(neg ? -v : v);
        }
        double value = static_cast<double>(mant);
        if (mant != 0) {
            if (exp10 < 0) {
                int k = -exp10;
                while (k > 22) {
                    value /= 1e22;
                    k -= 22;
                }
                value /= pow10_exact(k);
            } else if (exp10 > 0) {
                int k = exp10;
                while (k > 22) {
                    value *= 1e22;
                    k -= 22;
                }
                value *= pow10_exact(k);
            }
        }
        return Json::make_double(neg ? -value : value);
    }

    static void add_digit(char c, uint64_t* mant, int* digits, int* exp10, bool fractional) {
        if (*digits < 19) {
            *mant = *mant * 10u + static_cast<uint64_t>(c - '0');
            if (*mant != 0) ++*digits;
            if (fractional) --*exp10;
        } else if (!fractional) {
            ++*exp10;  // integer digit beyond precision: only scales the value
        }
    }

    const char* p_;
    const char* end_;
    const char* begin_;
    size_t max_depth_;
};

}  // namespace

Json Json::parse(const char* data, size_t len, size_t max_depth) {
    size_t bad = 0;
    if (!utf8_valid(reinterpret_cast<const uint8_t*>(data), len, &bad)) {
        throw Error(Status::InvalidArgument, "invalid UTF-8 at byte " + std::to_string(bad));
    }
    Parser parser(data, len, max_depth);
    return parser.parse_document();
}

// ------------------------------------------------------------------------------------------------
// writer
// ------------------------------------------------------------------------------------------------
namespace {
void append_quoted(std::string& out, const char* p, size_t n) {
    static const char* hex = "0123456789abcdef";
    out.push_back('"');
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(p[i]);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out.push_back(hex[(c >> 4) & 0xF]);
                    out.push_back(hex[c & 0xF]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}
}  // namespace

std::string json_quote(const std::string& s) {
    std::string out;
    append_quoted(out, s.data(), s.size());
    return out;
}

void JsonWriter::before_value() {
    if (after_key_) {
        after_key_ = false;
        return;
    }
    if (!need_comma_.empty()) {
        if (need_comma_.back()) out_.push_back(',');
        need_comma_.back() = true;
    }
}

void JsonWriter::open(char c) {
    before_value();
    out_.push_back(c);
    need_comma_.push_back(false);
}

void JsonWriter::close(char c) {
    out_.push_back(c);
    if (!need_comma_.empty()) need_comma_.pop_back();
}

void JsonWriter::key(const std::string& k) {
    if (!need_comma_.empty()) {
        if (need_comma_.back()) out_.push_back(',');
        need_comma_.back() = true;
    }
    append_quoted(out_, k.data(), k.size());
    out_.push_back(':');
    after_key_ = true;
}

void JsonWriter::value_string(const char* p, size_t n) {
    before_value();
    append_quoted(out_, p, n);
}

void JsonWriter::value_int(int64_t v) {
    before_value();
    out_ += std::to_string(v);
}

void JsonWriter::value_uint(uint64_t v) {
    before_value();
    out_ += std::to_string(v);
}

void JsonWriter::value_bool(bool v) {
    before_value();
    out_ += v ? "true" : "false";
}

void JsonWriter::value_null() {
    before_value();
    out_ += "null";
}

void JsonWriter::value_double(double v, int decimals) {
    before_value();
    if (!std::isfinite(v)) {
        out_ += "null";
        return;
    }
    if (decimals < 0) decimals = 0;
    if (decimals > 9) decimals = 9;
    bool neg = v < 0;
    double a = neg ? -v : v;
    uint64_t scale = 1;
    for (int i = 0; i < decimals; ++i) scale *= 10u;
    // llround-free rounding: values here are small (scores, durations), keep within uint64 range
    const double scaled = a * static_cast<double>(scale) + 0.5;
    uint64_t n = scaled >= 1.8e19 ? 18000000000000000000ull : static_cast<uint64_t>(scaled);
    const uint64_t ip = n / scale;
    uint64_t fp = n % scale;
    std::string text;
    if (neg && n != 0) text.push_back('-');
    text += std::to_string(ip);
    if (decimals > 0 && fp != 0) {
        std::string frac = std::to_string(fp);
        frac.insert(frac.begin(), static_cast<size_t>(decimals) - frac.size(), '0');
        while (!frac.empty() && frac.back() == '0') frac.pop_back();
        text.push_back('.');
        text += frac;
    }
    out_ += text;
}

void JsonWriter::raw_value(const std::string& json) {
    before_value();
    out_ += json;
}

// ------------------------------------------------------------------------------------------------
// dumpers for DOM values
// ------------------------------------------------------------------------------------------------
namespace {

void dump_value(const Json& v, std::string& out, bool canonical, int indent) {
    switch (v.type()) {
        case Json::Type::Null: out += "null"; return;
        case Json::Type::Bool: out += v.as_bool() ? "true" : "false"; return;
        case Json::Type::Int: out += std::to_string(v.as_int()); return;
        case Json::Type::Double: {
            std::string tmp;
            JsonWriter w(tmp);
            w.value_double(v.as_double(), 9);
            out += tmp;
            return;
        }
        case Json::Type::String: out += json_quote(v.as_string()); return;
        case Json::Type::Array: {
            const auto& items = v.items();
            if (items.empty()) {
                out += "[]";
                return;
            }
            out += "[";
            for (size_t i = 0; i < items.size(); ++i) {
                if (i) out += ",";
                if (!canonical) out += "\n" + std::string(static_cast<size_t>(indent + 2), ' ');
                dump_value(items[i], out, canonical, indent + 2);
            }
            if (!canonical) out += "\n" + std::string(static_cast<size_t>(indent), ' ');
            out += "]";
            return;
        }
        case Json::Type::Object: {
            std::vector<const std::pair<std::string, Json>*> members;
            for (const auto& kv : v.members()) members.push_back(&kv);
            if (canonical) {
                std::sort(members.begin(), members.end(),
                          [](const std::pair<std::string, Json>* a, const std::pair<std::string, Json>* b) {
                              return a->first < b->first;
                          });
            }
            if (members.empty()) {
                out += "{}";
                return;
            }
            out += "{";
            for (size_t i = 0; i < members.size(); ++i) {
                if (i) out += ",";
                if (!canonical) out += "\n" + std::string(static_cast<size_t>(indent + 2), ' ');
                out += json_quote(members[i]->first);
                out += canonical ? ":" : ": ";
                dump_value(members[i]->second, out, canonical, indent + 2);
            }
            if (!canonical) out += "\n" + std::string(static_cast<size_t>(indent), ' ');
            out += "}";
            return;
        }
    }
}

}  // namespace

std::string json_dump_canonical(const Json& v) {
    std::string out;
    dump_value(v, out, true, 0);
    return out;
}

std::string json_dump_pretty(const Json& v) {
    std::string out;
    dump_value(v, out, false, 0);
    out += "\n";
    return out;
}

}  // namespace apg
