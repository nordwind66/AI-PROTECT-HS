// pcre2_fallback backend: every pattern is executed by PCRE2, one after the other.
//
// This is NOT the production engine: it is slower (no multi-pattern automaton) and exists to
//   * let the library run on platforms where Hyperscan is not available (backend is reported as
//     "pcre2_fallback" in every result and in the manifest, never as "hyperscan"),
//   * act as the differential-test oracle for the Hyperscan backend.
#pragma once

#include <memory>
#include <vector>

#include "../ruleset/ruleset_model.h"
#include "matcher.h"
#include "pcre2_set.h"

namespace apg {

class Pcre2Backend : public PatternBackend {
public:
    Pcre2Backend(const RuleSetData& data, const Pcre2Limits& limits);
    const char* name() const override { return "pcre2_fallback"; }
    std::unique_ptr<BackendScratch> new_scratch() const override;
    bool scan(int profile, const char* data, size_t len, BackendScratch& scratch, std::vector<Candidate>& out,
              size_t max_hits) const override;
    const Pcre2Set& set() const { return set_; }

private:
    static std::vector<int> all_indices(const RuleSetData& data);
    const RuleSetData& data_;
    Pcre2Set set_;
    std::vector<std::vector<int>> by_profile_;
};

}  // namespace apg
