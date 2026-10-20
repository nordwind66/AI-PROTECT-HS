#include "pcre2_set.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include <algorithm>

namespace apg {

class Pcre2ScratchImpl : public Pcre2Set::Scratch {
public:
    Pcre2ScratchImpl(size_t ovector_pairs, const Pcre2Limits& lim) : match_data_(nullptr), mctx_(nullptr), jit_stack_(nullptr) {
        match_data_ = pcre2_match_data_create(static_cast<uint32_t>(ovector_pairs), nullptr);
        mctx_ = pcre2_match_context_create(nullptr);
        if (match_data_ == nullptr || mctx_ == nullptr) {
            release();
            throw Error(Status::Oom, "cannot allocate PCRE2 match data");
        }
        pcre2_set_match_limit(mctx_, lim.match_limit);
        pcre2_set_depth_limit(mctx_, lim.depth_limit);
        pcre2_set_heap_limit(mctx_, lim.heap_limit_kb);
        if (lim.use_jit) {
            jit_stack_ = pcre2_jit_stack_create(32 * 1024, 512 * 1024, nullptr);
            if (jit_stack_ != nullptr) pcre2_jit_stack_assign(mctx_, nullptr, jit_stack_);
        }
    }
    ~Pcre2ScratchImpl() override { release(); }
    Pcre2ScratchImpl(const Pcre2ScratchImpl&) = delete;
    Pcre2ScratchImpl& operator=(const Pcre2ScratchImpl&) = delete;

    pcre2_match_data* match_data_;
    pcre2_match_context* mctx_;
    pcre2_jit_stack* jit_stack_;

private:
    void release() {
        if (jit_stack_ != nullptr) pcre2_jit_stack_free(jit_stack_);
        if (mctx_ != nullptr) pcre2_match_context_free(mctx_);
        if (match_data_ != nullptr) pcre2_match_data_free(match_data_);
        jit_stack_ = nullptr;
        mctx_ = nullptr;
        match_data_ = nullptr;
    }
};

Pcre2Set::Pcre2Set(const RuleSetData& data, const std::vector<int>& pattern_indices, const Pcre2Limits& limits)
    : limits_(limits) {
    codes_.assign(data.patterns.size(), nullptr);
    for (int idx : pattern_indices) {
        if (idx < 0 || static_cast<size_t>(idx) >= data.patterns.size()) continue;
        const PatternDef& p = data.patterns[static_cast<size_t>(idx)];
        uint32_t options = PCRE2_UTF;
        if (p.flags & kFlagI) options |= PCRE2_CASELESS;
        if (p.flags & kFlagM) options |= PCRE2_MULTILINE;
        if (p.flags & kFlagS) options |= PCRE2_DOTALL;
        if (p.flags & kFlagU) options |= PCRE2_UCP;
        int errcode = 0;
        PCRE2_SIZE erroffset = 0;
        pcre2_code* code = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(p.regex.data()), p.regex.size(), options,
                                         &errcode, &erroffset, nullptr);
        if (code == nullptr) {
            failures_.emplace_back(idx, "pattern " + std::to_string(p.id) + ": " + error_message(errcode) +
                                             " at offset " + std::to_string(erroffset));
            continue;
        }
        if (limits_.use_jit) {
            // JIT is optional: when it is unavailable the interpreter is used.
            (void)pcre2_jit_compile(code, PCRE2_JIT_COMPLETE);
        }
        uint32_t captures = 0;
        pcre2_pattern_info(code, PCRE2_INFO_CAPTURECOUNT, &captures);
        max_ovector_pairs_ = std::max<size_t>(max_ovector_pairs_, static_cast<size_t>(captures) + 1);
        codes_[static_cast<size_t>(idx)] = reinterpret_cast<pcre2_real_code_8*>(code);
        ++compiled_;
    }
}

Pcre2Set::~Pcre2Set() {
    for (pcre2_real_code_8* c : codes_) {
        if (c != nullptr) pcre2_code_free(reinterpret_cast<pcre2_code*>(c));
    }
}

std::unique_ptr<Pcre2Set::Scratch> Pcre2Set::new_scratch() const {
    return std::unique_ptr<Scratch>(new Pcre2ScratchImpl(max_ovector_pairs_, limits_));
}

Pcre2Set::Result Pcre2Set::match(int pattern_index, const char* data, size_t len, Scratch& scratch, uint64_t* end,
                                 int* pcre_error, uint64_t* start) const {
    if (!has(pattern_index)) return Result::NoMatch;
    Pcre2ScratchImpl& s = static_cast<Pcre2ScratchImpl&>(scratch);
    const pcre2_code* code = reinterpret_cast<const pcre2_code*>(codes_[static_cast<size_t>(pattern_index)]);
    // The subject is valid UTF-8 by construction (validated input / normalisation output): skip the check.
    const int rc = pcre2_match(code, reinterpret_cast<PCRE2_SPTR>(data), len, 0, PCRE2_NO_UTF_CHECK, s.match_data_, s.mctx_);
    if (rc >= 0) {
        if (end != nullptr) {
            const PCRE2_SIZE* ov = pcre2_get_ovector_pointer(s.match_data_);
            *end = static_cast<uint64_t>(ov[1]);
        }
        if (start != nullptr) {
            const PCRE2_SIZE* ov = pcre2_get_ovector_pointer(s.match_data_);
            *start = static_cast<uint64_t>(ov[0]);
        }
        return Result::Match;
    }
    if (rc == PCRE2_ERROR_NOMATCH) return Result::NoMatch;
    if (pcre_error != nullptr) *pcre_error = rc;
    return Result::Error;
}

std::string Pcre2Set::version() {
    char buf[64] = {0};
    pcre2_config(PCRE2_CONFIG_VERSION, buf);
    return std::string(buf);
}

std::string Pcre2Set::error_message(int code) {
    PCRE2_UCHAR buf[256];
    const int n = pcre2_get_error_message(code, buf, sizeof(buf));
    if (n < 0) return "PCRE2 error " + std::to_string(code);
    return std::string(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
}

}  // namespace apg
