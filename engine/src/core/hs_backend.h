// Hyperscan backend (compiled only when APG_WITH_HYPERSCAN is defined).
#pragma once

#ifdef APG_WITH_HYPERSCAN

#include <memory>
#include <string>
#include <vector>

#include <hs/hs.h>

#include "../ruleset/ruleset_model.h"
#include "matcher.h"

namespace apg {

class HsBackend : public PatternBackend {
public:
    // Takes ownership of the databases: for every profile the list of its database shards (empty = the profile has no
    // Hyperscan patterns). A scan runs every shard of the profile and merges the hits; each pattern lives in exactly one
    // shard. `data` must outlive the backend.
    HsBackend(const RuleSetData& data, std::vector<std::vector<hs_database_t*>> dbs_by_profile);
    ~HsBackend() override;
    HsBackend(const HsBackend&) = delete;
    HsBackend& operator=(const HsBackend&) = delete;

    const char* name() const override { return "hyperscan"; }
    std::unique_ptr<BackendScratch> new_scratch() const override;
    bool scan(int profile, const char* data, size_t len, BackendScratch& scratch, std::vector<Candidate>& out,
              size_t max_hits, CandidateSink* sink = nullptr) const override;

    // Deserialises a database built by the compiler. Throws Error(Version / Platform / Database).
    static hs_database_t* deserialize(const std::string& bytes);
    static std::string library_version();

private:
    const RuleSetData& data_;
    std::vector<std::vector<hs_database_t*>> dbs_;       // [profile][shard]
};

}  // namespace apg

#endif  // APG_WITH_HYPERSCAN
