// Backend-independent pattern matching interface.
//
// A backend answers one question: "which patterns of profile P match this view text?". Two implementations
// exist: HsBackend (Hyperscan, the production engine) and Pcre2Backend (explicitly named pcre2_fallback, used
// when Hyperscan is not available for the platform, and as differential-test oracle).
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace apg {

struct Candidate {
    uint32_t pattern_index;   // index into RuleSetData::patterns
    uint64_t end;             // end offset of the (first) match in the scanned view, in bytes
    bool exact;               // true: a real match; false: Hyperscan prefilter candidate that PCRE2 must confirm
};

// Per-thread scratch memory. The base class also carries resource-limit diagnostics of the last scan.
class BackendScratch {
public:
    virtual ~BackendScratch() {}
    // (pattern_index, pcre2 error code) of expressions whose execution hit a PCRE2 limit during the last scan.
    std::vector<std::pair<uint32_t, int>> exec_errors;
};

class PatternBackend {
public:
    virtual ~PatternBackend() {}
    virtual const char* name() const = 0;
    virtual std::unique_ptr<BackendScratch> new_scratch() const = 0;
    // Scans one view text with all patterns of `profile` (index into RuleSetData::profiles). Appends one
    // Candidate per matching pattern. Returns false if more than max_hits candidates were produced; the
    // output is then incomplete and the caller must report a limit status.
    virtual bool scan(int profile, const char* data, size_t len, BackendScratch& scratch,
                      std::vector<Candidate>& out, size_t max_hits) const = 0;
};

}  // namespace apg
