// Common definitions shared by every part of the engine (library, CLI, tests).
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

#define APG_ENGINE_VERSION "1.0.0"

namespace apg {

// Must equal APG_ABI_VERSION in include/ai_prompt_guard.h (checked by a static_assert in the API shim).
constexpr uint32_t kAbiVersion = (1u << 16) | (0u << 8) | 0u;
// Version of the normalisation algorithms + tables. Rule sets compiled against another version are refused.
constexpr uint32_t kNormTablesVersion = 1;
constexpr int kSnapshotFormatVersion = 1;
constexpr int kManifestVersion = 1;

// Mirrors apg_status_t of the public header.
enum class Status : int {
    Ok = 0,
    InvalidArgument = 1,
    Config = 2,
    Database = 3,
    Version = 4,
    Platform = 5,
    Oom = 6,
    Limit = 7,
    Internal = 8
};

inline const char* status_name(Status s) {
    switch (s) {
        case Status::Ok: return "APG_OK";
        case Status::InvalidArgument: return "APG_ERR_INVALID_ARGUMENT";
        case Status::Config: return "APG_ERR_CONFIG";
        case Status::Database: return "APG_ERR_DATABASE";
        case Status::Version: return "APG_ERR_VERSION";
        case Status::Platform: return "APG_ERR_PLATFORM";
        case Status::Oom: return "APG_ERR_OOM";
        case Status::Limit: return "APG_ERR_LIMIT";
        case Status::Internal: return "APG_ERR_INTERNAL";
    }
    return "APG_ERR_INTERNAL";
}

// Exception type used INSIDE the library. It never crosses the C ABI: every exported function catches it
// and converts it to a status code plus a thread-local diagnostic string.
class Error : public std::runtime_error {
public:
    Error(Status st, const std::string& msg) : std::runtime_error(msg), status_(st) {}
    Status status() const { return status_; }

private:
    Status status_;
};

}  // namespace apg
