#include "engine.h"

#include <chrono>
#include <ctime>

#include "../core/json.h"
#include "../core/scanner.h"
#include "../core/utf8.h"
#include "../ruleset/manifest.h"

namespace apg {

namespace {

std::string utc_now_text() {
    const std::time_t t = std::time(nullptr);
    std::tm tmv;
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return std::string(buf);
}

bool valid_name(const std::string& s, size_t max_len) {
    if (s.empty() || s.size() > max_len) return false;
    for (char c : s) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

std::string scalar_text(const Json& v, const std::string& what) {
    switch (v.type()) {
        case Json::Type::String: return v.as_string();
        case Json::Type::Bool: return v.as_bool() ? "true" : "false";
        case Json::Type::Int: return std::to_string(v.as_int());
        default: throw Error(Status::InvalidArgument, what + " must be a string, integer or boolean");
    }
}

[[noreturn]] void bad_request(const std::string& msg) { throw Error(Status::InvalidArgument, "request: " + msg); }

}  // namespace

std::unique_ptr<Engine> Engine::create(const Config& cfg) {
    std::unique_ptr<Engine> e(new Engine(cfg));
    e->current_ = load_ruleset(cfg.manifest_path, cfg);
    e->loaded_at_ = utc_now_text();
    return e;
}

Engine::~Engine() { close_and_wait(); }

void Engine::close_and_wait() {
    std::unique_lock<std::mutex> lock(life_mu_);
    closing_ = true;
    life_cv_.wait(lock, [this] { return inflight_ == 0; });
}

std::shared_ptr<const LoadedRuleset> Engine::current() const {
    std::lock_guard<std::mutex> lock(swap_mu_);
    return current_;
}

std::string Engine::scan_text(const uint8_t* utf8, size_t len, const char* source, ScanVerdict* verdict) {
    Inflight guard(*this);
    if (utf8 == nullptr && len != 0) throw Error(Status::InvalidArgument, "utf8 is NULL but utf8_len is not 0");
    ScanInput in;
    in.text = reinterpret_cast<const char*>(utf8);
    in.text_len = len;
    if (source != nullptr) {
        in.source = source;
        if (!valid_name(in.source, 64)) throw Error(Status::InvalidArgument, "source must match [A-Za-z0-9_.-]{1,64}");
    }
    std::shared_ptr<const LoadedRuleset> rs = current();
    LoadedRuleset::Lease lease = rs->lease();
    return run_scan(*rs, cfg_, in, lease.get(), verdict);
}

std::string Engine::scan_json(const uint8_t* json, size_t len) {
    Inflight guard(*this);
    if (json == nullptr || len == 0) throw Error(Status::InvalidArgument, "request_json is empty");
    if (len > cfg_.limits.max_request_bytes) {
        throw Error(Status::Limit, "request of " + std::to_string(len) + " bytes exceeds limits.max_request_bytes");
    }
    const Json doc = Json::parse(reinterpret_cast<const char*>(json), len, 16);
    if (!doc.is_object()) bad_request("top level must be an object");
    ScanInput in;
    std::string text_storage;
    bool has_text = false;
    for (const auto& kv : doc.members()) {
        const std::string& k = kv.first;
        const Json& v = kv.second;
        if (k == "schema_version") {
            if (!v.is_int() || v.as_int() != 1) bad_request("schema_version must be 1");
        } else if (k == "request_id") {
            if (!v.is_string() || v.as_string().size() > 256) bad_request("request_id must be a string of at most 256 bytes");
            in.has_request_id = true;
            in.request_id = v.as_string();
        } else if (k == "source") {
            if (!v.is_string() || !valid_name(v.as_string(), 64)) bad_request("source must match [A-Za-z0-9_.-]{1,64}");
            in.source = v.as_string();
        } else if (k == "role") {
            if (!v.is_string() || v.as_string().size() > 64) bad_request("role must be a string of at most 64 bytes");
            in.role = v.as_string();
        } else if (k == "text") {
            if (!v.is_string()) bad_request("text must be a string");
            text_storage = v.as_string();
            has_text = true;
        } else if (k == "fields") {
            if (!v.is_object()) bad_request("fields must be an object");
            if (v.members().size() > cfg_.limits.max_fields) throw Error(Status::Limit, "too many fields");
            for (const auto& fv : v.members()) {
                if (!valid_name(fv.first, 64)) bad_request("field names must match [A-Za-z0-9_.-]{1,64}");
                if (!fv.second.is_string()) bad_request("field '" + fv.first + "' must be a string");
                in.fields.push_back(FieldIn{fv.first, fv.second.as_string()});
            }
        } else if (k == "context") {
            if (!v.is_object()) bad_request("context must be an object");
            if (v.members().size() > 64) throw Error(Status::Limit, "too many context entries");
            for (const auto& cv : v.members()) {
                if (!valid_name(cv.first, 64)) bad_request("context keys must match [A-Za-z0-9_.-]{1,64}");
                in.context.emplace_back(cv.first, scalar_text(cv.second, "context value"));
            }
        } else {
            bad_request("unknown key '" + k + "'");
        }
    }
    if (!has_text && in.fields.empty()) bad_request("either 'text' or 'fields' is required");
    in.text = text_storage.data();
    in.text_len = text_storage.size();
    std::shared_ptr<const LoadedRuleset> rs = current();
    LoadedRuleset::Lease lease = rs->lease();
    return run_scan(*rs, cfg_, in, lease.get());
}

void Engine::reload(const std::string& manifest_path_utf8) {
    Inflight guard(*this);
    std::lock_guard<std::mutex> serialise(reload_mu_);
    // The whole new rule set (manifest, hashes, databases, PCRE2 objects, a first scratch space) is built and
    // verified BEFORE the pointer is swapped: in-flight scans keep their shared_ptr to the old one.
    std::shared_ptr<const LoadedRuleset> fresh = load_ruleset(manifest_path_utf8, cfg_);
    const std::string stamp = utc_now_text();
    {
        std::lock_guard<std::mutex> lock(swap_mu_);
        current_ = fresh;
        loaded_at_ = stamp;
    }
}

std::string Engine::info_json() {
    Inflight guard(*this);
    std::shared_ptr<const LoadedRuleset> rs;
    std::string loaded_at;
    {
        std::lock_guard<std::mutex> lock(swap_mu_);     // the rule set and its load time are swapped together
        rs = current_;
        loaded_at = loaded_at_;
    }
    const ManifestInfo& i = rs->info;
    std::string out;
    JsonWriter w(out);
    w.begin_object();
    w.kv_int("schema_version", 1);
    w.kv_string("engine_version", APG_ENGINE_VERSION);
    w.kv_uint("abi_version", kAbiVersion);
    w.kv_uint("norm_tables_version", kNormTablesVersion);
    w.key("ruleset");
    w.begin_object();
    w.kv_string("version", i.ruleset_version);
    w.kv_string("content_digest", i.content_digest);
    w.kv_string("snapshot_sha256", i.snapshot_sha256);
    w.kv_int("rules", i.rule_count);
    w.kv_int("patterns", i.pattern_count);
    w.kv_int("patterns_native", i.patterns_native);
    w.kv_int("patterns_prefilter", i.patterns_prefilter);
    w.kv_int("patterns_failed", i.patterns_failed);
    w.key("failed_pattern_ids");
    w.begin_array();
    for (uint32_t id : i.failed_pattern_ids) w.value_uint(id);
    w.end_array();
    w.kv_string("manifest_path", i.manifest_path);
    w.kv_string("built_at", i.built_at);
    w.kv_string("loaded_at", loaded_at);
    w.end_object();
    w.key("backend");
    w.begin_object();
    w.kv_string("name", i.backend_name);
    w.kv_string("hyperscan_version", i.hs_version);
    w.kv_string("pcre2_version", i.pcre2_version);
    w.kv_string("cpu_target", i.cpu_target);
    w.kv_string("os", i.os);
    w.kv_string("arch", i.arch);
    w.end_object();
    w.key("policy");
    w.begin_object();
    w.kv_bool("allow_block", cfg_.policy.allow_block);
    w.kv_string("on_error", cfg_.policy.on_error);
    w.kv_string("on_verify_error", cfg_.policy.on_verify_error);
    w.end_object();
    w.key("limits");
    w.begin_object();
    w.kv_uint("max_text_bytes", cfg_.limits.max_text_bytes);
    w.kv_uint("max_request_bytes", cfg_.limits.max_request_bytes);
    w.kv_uint("max_hits", cfg_.limits.max_hits);
    w.kv_uint("max_fields", cfg_.limits.max_fields);
    w.end_object();
    w.end_object();
    return out;
}

}  // namespace apg
