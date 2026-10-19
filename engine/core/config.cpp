#include "config.h"

#include <set>

#include "json.h"

namespace apg {

namespace {

[[noreturn]] void bad(const std::string& msg) { throw Error(Status::Config, "config: " + msg); }

void only_keys(const Json& obj, const std::set<std::string>& allowed, const std::string& where) {
    for (const auto& kv : obj.members()) {
        if (allowed.count(kv.first) == 0) bad("unknown key '" + kv.first + "' in " + where);
    }
}

size_t get_size(const Json& v, const std::string& name, size_t lo, size_t hi) {
    if (!v.is_int()) bad(name + " must be an integer");
    const int64_t n = v.as_int();
    if (n < static_cast<int64_t>(lo) || (hi != 0 && static_cast<uint64_t>(n) > hi)) {
        bad(name + " out of range [" + std::to_string(lo) + ", " + std::to_string(hi) + "]");
    }
    return static_cast<size_t>(n);
}

double get_unit(const Json& v, const std::string& name) {
    if (!v.is_number()) bad(name + " must be a number");
    const double d = v.as_double();
    if (!(d >= 0.0 && d <= 1.0)) bad(name + " must be within [0, 1]");
    return d;
}

bool get_bool(const Json& v, const std::string& name) {
    if (!v.is_bool()) bad(name + " must be a boolean");
    return v.as_bool();
}

}  // namespace

Config parse_config(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) bad("empty configuration");
    Json doc;
    try {
        doc = Json::parse(reinterpret_cast<const char*>(data), len, 16);
    } catch (const Error& e) {
        bad(e.what());
    }
    if (!doc.is_object()) bad("top level must be an object");
    only_keys(doc, {"schema_version", "manifest_path", "limits", "policy", "output", "pcre2"}, "the top level");
    Config c;
    if (const Json* v = doc.get("schema_version")) {
        if (!v->is_int() || v->as_int() != 1) bad("schema_version must be 1");
    }
    const Json* mp = doc.get("manifest_path");
    if (mp == nullptr || !mp->is_string() || mp->as_string().empty()) bad("manifest_path (string) is required");
    c.manifest_path = mp->as_string();

    if (const Json* l = doc.get("limits")) {
        if (!l->is_object()) bad("limits must be an object");
        only_keys(*l, {"max_text_bytes", "max_request_bytes", "max_hits", "max_fields", "scratch_pool_max", "verify_budget_ms"},
                  "limits");
        if (const Json* v = l->get("max_text_bytes")) c.limits.max_text_bytes = get_size(*v, "limits.max_text_bytes", 1, 1ull << 30);
        if (const Json* v = l->get("max_request_bytes")) c.limits.max_request_bytes = get_size(*v, "limits.max_request_bytes", 16, 1ull << 31);
        if (const Json* v = l->get("max_hits")) c.limits.max_hits = get_size(*v, "limits.max_hits", 1, 100000000);
        if (const Json* v = l->get("max_fields")) c.limits.max_fields = get_size(*v, "limits.max_fields", 0, 1024);
        if (const Json* v = l->get("scratch_pool_max")) c.limits.scratch_pool_max = get_size(*v, "limits.scratch_pool_max", 1, 4096);
        if (const Json* v = l->get("verify_budget_ms")) c.limits.verify_budget_us = get_size(*v, "limits.verify_budget_ms", 1, 600000) * 1000ull;
    }
    if (c.limits.max_request_bytes < c.limits.max_text_bytes) {
        bad("limits.max_request_bytes must be >= limits.max_text_bytes");
    }
    if (const Json* p = doc.get("policy")) {
        if (!p->is_object()) bad("policy must be an object");
        only_keys(*p, {"allow_block", "on_error", "on_verify_error", "thresholds", "needs_context_review_at"}, "policy");
        if (const Json* v = p->get("needs_context_review_at")) {
            c.policy.needs_context_review_at = get_unit(*v, "policy.needs_context_review_at");
            c.policy.override_needs_context = true;
        }
        if (const Json* v = p->get("allow_block")) c.policy.allow_block = get_bool(*v, "policy.allow_block");
        if (const Json* v = p->get("on_error")) {
            if (!v->is_string()) bad("policy.on_error must be a string");
            c.policy.on_error = v->as_string();
            const std::string& s = c.policy.on_error;
            if (s != "allow" && s != "review" && s != "alert" && s != "block") bad("policy.on_error must be allow|review|alert|block");
            if (s == "block" && !c.policy.allow_block) bad("policy.on_error=block requires policy.allow_block=true");
        }
        if (const Json* v = p->get("on_verify_error")) {
            if (!v->is_string()) bad("policy.on_verify_error must be a string");
            c.policy.on_verify_error = v->as_string();
            if (c.policy.on_verify_error != "ignore" && c.policy.on_verify_error != "review") {
                bad("policy.on_verify_error must be ignore|review");
            }
        }
        if (const Json* t = p->get("thresholds")) {
            if (!t->is_object()) bad("policy.thresholds must be an object");
            only_keys(*t, {"review", "alert", "block"}, "policy.thresholds");
            if (const Json* v = t->get("review")) { c.policy.review = get_unit(*v, "thresholds.review"); c.policy.override_review = true; }
            if (const Json* v = t->get("alert")) { c.policy.alert = get_unit(*v, "thresholds.alert"); c.policy.override_alert = true; }
            if (const Json* v = t->get("block")) { c.policy.block = get_unit(*v, "thresholds.block"); c.policy.override_block = true; }
        }
    }
    if (const Json* o = doc.get("output")) {
        if (!o->is_object()) bad("output must be an object");
        only_keys(*o, {"include_offsets", "include_names", "include_evidence_text"}, "output");
        if (const Json* v = o->get("include_offsets")) c.output.include_offsets = get_bool(*v, "output.include_offsets");
        if (const Json* v = o->get("include_names")) c.output.include_names = get_bool(*v, "output.include_names");
        if (const Json* v = o->get("include_evidence_text")) c.output.include_evidence_text = get_bool(*v, "output.include_evidence_text");
    }
    if (const Json* p = doc.get("pcre2")) {
        if (!p->is_object()) bad("pcre2 must be an object");
        only_keys(*p, {"match_limit", "depth_limit", "heap_limit_kb", "use_jit"}, "pcre2");
        if (const Json* v = p->get("match_limit")) c.pcre2.match_limit = static_cast<uint32_t>(get_size(*v, "pcre2.match_limit", 1000, 0xFFFFFFFFull));
        if (const Json* v = p->get("depth_limit")) c.pcre2.depth_limit = static_cast<uint32_t>(get_size(*v, "pcre2.depth_limit", 100, 0xFFFFFFFFull));
        if (const Json* v = p->get("heap_limit_kb")) c.pcre2.heap_limit_kb = static_cast<uint32_t>(get_size(*v, "pcre2.heap_limit_kb", 64, 0xFFFFFFFFull));
        if (const Json* v = p->get("use_jit")) c.pcre2.use_jit = get_bool(*v, "pcre2.use_jit");
    }
    return c;
}

}  // namespace apg
