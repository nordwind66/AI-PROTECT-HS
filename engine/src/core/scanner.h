// The detection pipeline for ONE request:
//   validate -> normalised views -> backend scan (+ PCRE2 confirmation) -> three-valued rule conditions ->
//   context gating -> risk scoring -> decision -> JSON result.
#pragma once

#include <string>
#include <utility>
#include <vector>

#include "../ruleset/loaded_ruleset.h"
#include "config.h"

namespace apg {

struct FieldIn {
    std::string name;
    std::string value;
};

struct ScanInput {
    const char* text = nullptr;          // primary text (explicit length, may contain NUL bytes)
    size_t text_len = 0;
    std::string source;                  // empty = user_input
    std::string role;                    // informational only
    bool has_request_id = false;
    std::string request_id;
    std::vector<FieldIn> fields;                                      // extra named fields (tool_name, ...)
    std::vector<std::pair<std::string, std::string>> context;         // scalar request context (string forms)
};

// Produces the JSON result document. Problems with the INPUT (invalid UTF-8, oversize text, scan limits) are
// reported inside the document; only internal failures (out of memory, bugs) throw apg::Error.
std::string run_scan(const LoadedRuleset& rs, const Config& cfg, const ScanInput& in, ThreadScratch& scratch);

}  // namespace apg
