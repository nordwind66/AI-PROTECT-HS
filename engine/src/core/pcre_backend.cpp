#include "pcre_backend.h"

namespace apg {

namespace {
class Pcre2BackendScratch : public BackendScratch {
public:
    explicit Pcre2BackendScratch(std::unique_ptr<Pcre2Set::Scratch> s) : inner(std::move(s)) {}
    std::unique_ptr<Pcre2Set::Scratch> inner;
};
}  // namespace

std::vector<int> Pcre2Backend::all_indices(const RuleSetData& data) {
    std::vector<int> v;
    v.reserve(data.patterns.size());
    for (size_t i = 0; i < data.patterns.size(); ++i) v.push_back(static_cast<int>(i));
    return v;
}

Pcre2Backend::Pcre2Backend(const RuleSetData& data, const Pcre2Limits& limits)
    : data_(data), set_(data, all_indices(data), limits), by_profile_(data.profiles.size()) {
    for (size_t i = 0; i < data.patterns.size(); ++i) {
        if (set_.has(static_cast<int>(i))) by_profile_[static_cast<size_t>(data.patterns[i].profile)].push_back(static_cast<int>(i));
    }
}

std::unique_ptr<BackendScratch> Pcre2Backend::new_scratch() const {
    return std::unique_ptr<BackendScratch>(new Pcre2BackendScratch(set_.new_scratch()));
}

bool Pcre2Backend::scan(int profile, const char* data, size_t len, BackendScratch& scratch, std::vector<Candidate>& out,
                        size_t max_hits, CandidateSink* sink) const {
    if (profile < 0 || static_cast<size_t>(profile) >= by_profile_.size()) return true;
    Pcre2BackendScratch& sc = static_cast<Pcre2BackendScratch&>(scratch);
    for (int idx : by_profile_[static_cast<size_t>(profile)]) {
        uint64_t end = 0;
        int err = 0;
        const Pcre2Set::Result r = set_.match(idx, data, len, *sc.inner, &end, &err);
        if (r == Pcre2Set::Result::Match) {
            if (out.size() >= max_hits) return false;
            Candidate c;
            c.pattern_index = static_cast<uint32_t>(idx);
            c.end = end;
            c.exact = true;
            if (sink != nullptr) {
                if (sink->on_candidate(c)) return true;
            } else {
                out.push_back(c);
            }
        } else if (r == Pcre2Set::Result::Error) {
            sc.exec_errors.emplace_back(static_cast<uint32_t>(idx), err);
        }
    }
    (void)data_;
    return true;
}

}  // namespace apg
