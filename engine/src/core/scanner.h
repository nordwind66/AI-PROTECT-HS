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

// The outcome of a scan without JSON (decision codes as in the public header: 0 allow, 1 review, 2 alert, 3 block).
struct ScanVerdict {
    int decision = 0;
    bool scan_error = false;       // the text could not be scanned; decision comes from policy.on_error
    double score = 0.0;
    uint32_t matched_rules = 0;
};

// Produces the JSON result document. With `verdict` != nullptr only the verdict is computed (no JSON, no evidence text,
// the returned string is empty). Problems with the INPUT (invalid UTF-8, oversize text, scan limits) are
// reported inside the document; only internal failures (out of memory, bugs) throw apg::Error.
std::string run_scan(const LoadedRuleset& rs, const Config& cfg, const ScanInput& in, ThreadScratch& scratch,
                     ScanVerdict* verdict = nullptr);

}  // namespace apg
