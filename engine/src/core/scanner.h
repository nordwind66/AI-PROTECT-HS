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
// One matched rule for the lean result (same layout as apg_hit_t of the public header).
struct HitOut {
    char rule_id[32];
    char matched_text[256];
};

struct ScanVerdict {
    HitOut* hits = nullptr;        // optional output array: the matched rules, highest risk first
    size_t hits_cap = 0;
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

// The first-match scan: stops as soon as ONE rule is satisfied (also inside the Hyperscan scan) and reports that rule.
// Same layout as apg_match_t of the public header.
struct MatchOut {
    int32_t matched;
    int32_t scan_error;
    char rule_id[32];
    char matched_text[256];
};

// Plain text only (no named fields, no request context: rules that need context never match here). A rule counts when its condition
// is true and its risk (weight * confidence * source multiplier) is at least `min_risk`. Rules with a `not` in the condition are
// decided after the whole text was scanned, all others at the moment their last pattern hits.
void run_first_match(const LoadedRuleset& rs, const Config& cfg, const char* text, size_t len, const char* source, double min_risk,
                     ThreadScratch& scratch, MatchOut* out);

}  // namespace apg
