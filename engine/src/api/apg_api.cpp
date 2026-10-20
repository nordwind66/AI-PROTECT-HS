// The C ABI shim. Every exported function:
//   * never lets a C++ exception escape (try/catch -> status code + thread-local diagnostic),
//   * initialises its out-parameters before doing anything that can fail,
//   * allocates result buffers with the LIBRARY'S allocator; callers release them with apg_free_buffer().
#include "../../include/ai_prompt_guard.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <string>

#include "engine.h"

static_assert(APG_ABI_VERSION == apg::kAbiVersion, "include/ai_prompt_guard.h and src/core/common.h disagree on the ABI version");

struct apg_context {
    std::unique_ptr<apg::Engine> engine;
};

namespace {

thread_local std::string g_last_error;

void set_error(const std::string& message) noexcept {
    try {
        g_last_error = message;
    } catch (...) {
        g_last_error.clear();
    }
}

void clear_error() noexcept { g_last_error.clear(); }

apg_status_t to_c(apg::Status s) noexcept {
    switch (s) {
        case apg::Status::Ok: return APG_OK;
        case apg::Status::InvalidArgument: return APG_ERR_INVALID_ARGUMENT;
        case apg::Status::Config: return APG_ERR_CONFIG;
        case apg::Status::Database: return APG_ERR_DATABASE;
        case apg::Status::Version: return APG_ERR_VERSION;
        case apg::Status::Platform: return APG_ERR_PLATFORM;
        case apg::Status::Oom: return APG_ERR_OOM;
        case apg::Status::Limit: return APG_ERR_LIMIT;
        case apg::Status::Internal: return APG_ERR_INTERNAL;
    }
    return APG_ERR_INTERNAL;
}

template <class F>
apg_status_t guarded(F&& body) noexcept {
    try {
        clear_error();
        body();
        return APG_OK;
    } catch (const apg::Error& e) {
        set_error(e.what());
        return to_c(e.status());
    } catch (const std::bad_alloc&) {
        set_error("out of memory");
        return APG_ERR_OOM;
    } catch (const std::exception& e) {
        set_error(e.what());
        return APG_ERR_INTERNAL;
    } catch (...) {
        set_error("unknown internal error");
        return APG_ERR_INTERNAL;
    }
}

// Copies `s` into a malloc'ed, NUL-terminated buffer owned by the caller (release with apg_free_buffer).
uint8_t* make_buffer(const std::string& s, size_t* out_len) {
    uint8_t* p = static_cast<uint8_t*>(std::malloc(s.size() + 1));
    if (p == nullptr) throw std::bad_alloc();
    if (!s.empty()) std::memcpy(p, s.data(), s.size());
    p[s.size()] = 0;
    *out_len = s.size();
    return p;
}

apg_status_t invalid(const char* what) noexcept {
    set_error(what);
    return APG_ERR_INVALID_ARGUMENT;
}

}  // namespace

extern "C" {

APG_API uint32_t APG_CALL apg_abi_version(void) { return APG_ABI_VERSION; }

APG_API const char* APG_CALL apg_engine_version(void) { return APG_ENGINE_VERSION; }

APG_API const char* APG_CALL apg_status_string(apg_status_t status) {
    switch (status) {
        case APG_OK: return "APG_OK";
        case APG_ERR_INVALID_ARGUMENT: return "APG_ERR_INVALID_ARGUMENT";
        case APG_ERR_CONFIG: return "APG_ERR_CONFIG";
        case APG_ERR_DATABASE: return "APG_ERR_DATABASE";
        case APG_ERR_VERSION: return "APG_ERR_VERSION";
        case APG_ERR_PLATFORM: return "APG_ERR_PLATFORM";
        case APG_ERR_OOM: return "APG_ERR_OOM";
        case APG_ERR_LIMIT: return "APG_ERR_LIMIT";
        case APG_ERR_INTERNAL: return "APG_ERR_INTERNAL";
    }
    return "APG_ERR_UNKNOWN";
}

APG_API const char* APG_CALL apg_last_error(void) { return g_last_error.c_str(); }

APG_API apg_status_t APG_CALL apg_create(const uint8_t* config_json, size_t config_len, apg_context_t** out_ctx) {
    if (out_ctx == nullptr) return invalid("out_ctx is NULL");
    *out_ctx = nullptr;
    if (config_json == nullptr || config_len == 0) return invalid("config_json is empty");
    return guarded([&] {
        const apg::Config cfg = apg::parse_config(config_json, config_len);
        std::unique_ptr<apg::Engine> engine = apg::Engine::create(cfg);
        std::unique_ptr<apg_context> ctx(new apg_context());
        ctx->engine = std::move(engine);
        *out_ctx = ctx.release();
    });
}

APG_API apg_status_t APG_CALL apg_reload(apg_context_t* ctx, const char* manifest_path_utf8) {
    if (ctx == nullptr) return invalid("ctx is NULL");
    if (manifest_path_utf8 == nullptr || manifest_path_utf8[0] == '\0') return invalid("manifest_path_utf8 is empty");
    return guarded([&] { ctx->engine->reload(manifest_path_utf8); });
}

APG_API void APG_CALL apg_destroy(apg_context_t* ctx) {
    if (ctx == nullptr) return;
    try {
        if (ctx->engine) ctx->engine->close_and_wait();   // waits for scans/reloads that already started
    } catch (...) {
    }
    delete ctx;
}

APG_API apg_status_t APG_CALL apg_scan_text(apg_context_t* ctx, const uint8_t* utf8, size_t utf8_len, const char* source,
                                            uint8_t** out_json, size_t* out_len) {
    if (out_json != nullptr) *out_json = nullptr;
    if (out_len != nullptr) *out_len = 0;
    if (ctx == nullptr) return invalid("ctx is NULL");
    if (out_json == nullptr || out_len == nullptr) return invalid("out_json / out_len is NULL");
    return guarded([&] {
        const std::string result = ctx->engine->scan_text(utf8, utf8_len, source);
        *out_json = make_buffer(result, out_len);
    });
}

APG_API apg_status_t APG_CALL apg_scan_json(apg_context_t* ctx, const uint8_t* request_json, size_t request_len,
                                            uint8_t** out_json, size_t* out_len) {
    if (out_json != nullptr) *out_json = nullptr;
    if (out_len != nullptr) *out_len = 0;
    if (ctx == nullptr) return invalid("ctx is NULL");
    if (out_json == nullptr || out_len == nullptr) return invalid("out_json / out_len is NULL");
    return guarded([&] {
        const std::string result = ctx->engine->scan_json(request_json, request_len);
        *out_json = make_buffer(result, out_len);
    });
}

APG_API apg_status_t APG_CALL apg_get_info(apg_context_t* ctx, uint8_t** out_json, size_t* out_len) {
    if (out_json != nullptr) *out_json = nullptr;
    if (out_len != nullptr) *out_len = 0;
    if (ctx == nullptr) return invalid("ctx is NULL");
    if (out_json == nullptr || out_len == nullptr) return invalid("out_json / out_len is NULL");
    return guarded([&] {
        const std::string result = ctx->engine->info_json();
        *out_json = make_buffer(result, out_len);
    });
}

APG_API void APG_CALL apg_free_buffer(void* ptr) { std::free(ptr); }

}  // extern "C"
