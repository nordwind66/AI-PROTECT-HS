// A set of compiled PCRE2 expressions with strict resource limits.
//
// Used (a) to confirm Hyperscan prefilter candidates exactly, and (b) as the matcher of the pcre2_fallback
// backend. PCRE2 code objects are immutable and may be shared by threads; per-thread state lives in Scratch.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../ruleset/ruleset_model.h"

struct pcre2_real_code_8;

namespace apg {

struct Pcre2Limits {
    uint32_t match_limit = 1000000;
    uint32_t depth_limit = 10000;
    uint32_t heap_limit_kb = 20480;
    bool use_jit = true;
};

class Pcre2Set {
public:
    // Compiles the given patterns. Patterns that PCRE2 rejects are recorded in failures() and simply absent
    // from the set (never thrown), so one bad expression cannot take the whole rule set down.
    Pcre2Set(const RuleSetData& data, const std::vector<int>& pattern_indices, const Pcre2Limits& limits);
    ~Pcre2Set();
    Pcre2Set(const Pcre2Set&) = delete;
    Pcre2Set& operator=(const Pcre2Set&) = delete;

    class Scratch {
    public:
        virtual ~Scratch() {}
    };
    std::unique_ptr<Scratch> new_scratch() const;

    enum class Result { Match, NoMatch, Error };
    // Runs pattern `pattern_index` against the view text (valid UTF-8). *end receives the end offset of the
    // first match; *pcre_error the PCRE2 error code when the result is Error (match / depth / heap limit ...).
    // *start (optional) receives the start offset of that match.
    Result match(int pattern_index, const char* data, size_t len, Scratch& scratch, uint64_t* end,
                 int* pcre_error, uint64_t* start = nullptr) const;

    bool has(int pattern_index) const {
        return pattern_index >= 0 && static_cast<size_t>(pattern_index) < codes_.size() && codes_[pattern_index] != nullptr;
    }
    size_t compiled_count() const { return compiled_; }
    const std::vector<std::pair<int, std::string>>& failures() const { return failures_; }
    static std::string version();                              // e.g. "10.42 2022-12-11"
    static std::string error_message(int code);

private:
    friend class Pcre2ScratchImpl;
    std::vector<pcre2_real_code_8*> codes_;                    // indexed by pattern_index; nullptr if absent
    size_t compiled_ = 0;
    size_t max_ovector_pairs_ = 1;
    Pcre2Limits limits_;
    std::vector<std::pair<int, std::string>> failures_;
};

}  // namespace apg
