// Runtime configuration (the JSON document passed to apg_create). Unknown keys are rejected so that a typo
// can never silently disable a limit or a policy.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "pcre2_set.h"

namespace apg {

struct Limits {
    size_t max_text_bytes = 1u << 20;          // largest text (primary or any named field) that is scanned
    size_t max_request_bytes = 4u << 20;       // largest request JSON that is parsed
    size_t max_hits = 50000;                   // candidate matches per view scan before the scan is aborted
    size_t max_fields = 16;                    // named fields per request
    size_t scratch_pool_max = 64;              // idle scratch spaces kept for reuse
    uint64_t verify_budget_us = 200000;        // wall-clock budget for PCRE2 confirmation per request
};

struct Policy {
    bool allow_block = false;                  // alert-only unless explicitly enabled
    std::string on_error = "review";           // decision when a text cannot be scanned: allow|review|alert|block
    std::string on_verify_error = "review";    // a PCRE2 limit was hit while confirming a candidate: ignore|review
    bool override_review = false, override_alert = false, override_block = false;
    double review = 0.30, alert = 0.50, block = 0.85;
    bool override_needs_context = false;       // true: needs_context_review_at replaces the value stored in the rule set
    double needs_context_review_at = 0.50;
};

struct OutputOptions {
    bool include_offsets = true;               // evidence offsets (bytes) per matched pattern
    bool include_names = true;                 // rule names in matched_rules
    bool include_evidence_text = true;         // the matched fragment of the original text + its sentence in evidence[]
};

struct Config {
    std::string manifest_path;
    // false (default): the rule set is loaded as it is -- Hyperscan itself refuses a database it cannot use (other version,
    // CPU features), and no hash / version / platform bookkeeping of the manifest is checked. true: the full integrity and
    // compatibility verification of the manifest (used by `ai-prompt-guard verify` and the compiler's self test).
    bool verify_ruleset = false;
    Limits limits;
    Policy policy;
    OutputOptions output;
    Pcre2Limits pcre2;
};

// Throws Error(Status::Config) with a precise message.
Config parse_config(const uint8_t* json, size_t len);

}  // namespace apg
