// A fully loaded, immutable rule set: parsed snapshot + matching backend + PCRE2 verifier + scratch pool.
// Scans hold a shared_ptr to it, so a hot reload can swap the active rule set while old scans finish.
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "../core/matcher.h"
#include "../core/pcre2_set.h"
#include "ruleset_model.h"

namespace apg {

struct ManifestInfo {
    std::string manifest_path;
    std::string ruleset_version, content_digest, snapshot_sha256;
    std::string backend_name;                    // hyperscan | pcre2_fallback
    std::string os, arch, cpu_target, hs_version, pcre2_version, built_at;
    int rule_count = 0, pattern_count = 0;
    int patterns_native = 0, patterns_prefilter = 0, patterns_failed = 0;
    std::vector<uint32_t> failed_pattern_ids;    // listed in the manifest; their leaves can never match
};

struct ThreadScratch {
    std::unique_ptr<BackendScratch> backend;
    std::unique_ptr<Pcre2Set::Scratch> verify;   // null when the rule set has no prefilter patterns
    std::unique_ptr<Pcre2Set::Scratch> locate;   // null when there is no locator
};

class LoadedRuleset {
public:
    explicit LoadedRuleset(size_t pool_max) : pool_max_(pool_max) {}
    LoadedRuleset(const LoadedRuleset&) = delete;
    LoadedRuleset& operator=(const LoadedRuleset&) = delete;

    std::shared_ptr<RuleSetData> data;
    std::unique_ptr<PatternBackend> backend;     // must be destroyed before `data` (declared after it)
    std::unique_ptr<Pcre2Set> verifier;          // confirms Hyperscan prefilter candidates; may be null
    std::unique_ptr<Pcre2Set> locator;           // finds the exact span of a hit for the evidence text (all patterns, no JIT); may be null
    ManifestInfo info;
    std::vector<bool> disabled_pattern;          // indexed by pattern index: not compiled / failed

    // RAII lease of a scratch space: returned to the pool on destruction.
    class Lease {
    public:
        Lease(const LoadedRuleset* owner, std::unique_ptr<ThreadScratch> s) : owner_(owner), s_(std::move(s)) {}
        Lease(Lease&& o) noexcept : owner_(o.owner_), s_(std::move(o.s_)) {}
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        ~Lease() {
            if (s_) owner_->give_back(std::move(s_));
        }
        ThreadScratch& get() { return *s_; }

    private:
        const LoadedRuleset* owner_;
        std::unique_ptr<ThreadScratch> s_;
    };

    std::unique_ptr<ThreadScratch> make_scratch() const;
    Lease lease() const;

private:
    void give_back(std::unique_ptr<ThreadScratch> s) const;
    size_t pool_max_;
    mutable std::mutex mu_;
    mutable std::vector<std::unique_ptr<ThreadScratch>> pool_;
};

}  // namespace apg
