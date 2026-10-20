// Minimal strict JSON (RFC 8259) DOM parser + streaming writer.
//
// * Input must be well-formed UTF-8 (the whole buffer is validated first); duplicate object keys are rejected.
// * Numbers are parsed without touching the C locale (a host application may have called setlocale()).
// * The writer never uses printf-style double formatting for the same reason.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "common.h"

namespace apg {

class Json {
public:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };

    Json() : type_(Type::Null), b_(false), i_(0), d_(0.0) {}
    static Json make_bool(bool v) { Json j; j.type_ = Type::Bool; j.b_ = v; return j; }
    static Json make_int(int64_t v) { Json j; j.type_ = Type::Int; j.i_ = v; return j; }
    static Json make_double(double v) { Json j; j.type_ = Type::Double; j.d_ = v; return j; }
    static Json make_string(std::string v) { Json j; j.type_ = Type::String; j.s_ = std::move(v); return j; }
    static Json make_array() { Json j; j.type_ = Type::Array; return j; }
    static Json make_object() { Json j; j.type_ = Type::Object; return j; }

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_bool() const { return type_ == Type::Bool; }
    bool is_int() const { return type_ == Type::Int; }
    bool is_number() const { return type_ == Type::Int || type_ == Type::Double; }
    bool is_string() const { return type_ == Type::String; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_object() const { return type_ == Type::Object; }

    // Accessors throw Error(Status::InvalidArgument) on a type mismatch.
    bool as_bool() const;
    int64_t as_int() const;       // accepts Int only
    double as_double() const;     // accepts Int and Double
    const std::string& as_string() const;
    const std::vector<Json>& items() const;
    const std::vector<std::pair<std::string, Json>>& members() const;

    // Object lookup; nullptr if absent or not an object.
    const Json* get(const std::string& key) const;

    void push_back(Json v) { arr_.push_back(std::move(v)); }
    void set(const std::string& key, Json v) { obj_.emplace_back(key, std::move(v)); }

    // Throws Error(Status::InvalidArgument, "...") describing the first problem.
    static Json parse(const char* data, size_t len, size_t max_depth = 64);
    static Json parse(const std::string& s, size_t max_depth = 64) { return parse(s.data(), s.size(), max_depth); }

private:
    Type type_;
    bool b_;
    int64_t i_;
    double d_;
    std::string s_;
    std::vector<Json> arr_;
    std::vector<std::pair<std::string, Json>> obj_;
};

// Appends JSON text to a caller-owned string.
class JsonWriter {
public:
    explicit JsonWriter(std::string& out) : out_(out) {}

    void begin_object() { open('{'); }
    void end_object() { close('}'); }
    void begin_array() { open('['); }
    void end_array() { close(']'); }
    void key(const std::string& k);

    void value_string(const std::string& v) { value_string(v.data(), v.size()); }
    void value_string(const char* p, size_t n);
    void value_int(int64_t v);
    void value_uint(uint64_t v);
    void value_bool(bool v);
    void value_null();
    // Fixed-point decimal without locale dependence ("0.731"); trailing zeros are trimmed. Non-finite -> null.
    void value_double(double v, int decimals = 6);
    // Inserts already serialised JSON verbatim.
    void raw_value(const std::string& json);

    // Convenience: "key": value
    void kv_string(const std::string& k, const std::string& v) { key(k); value_string(v); }
    void kv_int(const std::string& k, int64_t v) { key(k); value_int(v); }
    void kv_uint(const std::string& k, uint64_t v) { key(k); value_uint(v); }
    void kv_bool(const std::string& k, bool v) { key(k); value_bool(v); }
    void kv_double(const std::string& k, double v, int decimals = 6) { key(k); value_double(v, decimals); }

private:
    void before_value();
    void open(char c);
    void close(char c);
    std::string& out_;
    std::vector<bool> need_comma_;   // one entry per open container
    bool after_key_ = false;
};

// Escapes `s` as a JSON string literal (with quotes).
std::string json_quote(const std::string& s);

// Canonical form: object keys sorted by byte order, no whitespace. Used for hashing (manifest build_hash).
std::string json_dump_canonical(const Json& v);
// Human friendly form: 2-space indentation, keys in insertion order.
std::string json_dump_pretty(const Json& v);

}  // namespace apg
