#include "loaded_ruleset.h"

namespace apg {

std::unique_ptr<ThreadScratch> LoadedRuleset::make_scratch() const {
    std::unique_ptr<ThreadScratch> s(new ThreadScratch());
    s->backend = backend->new_scratch();
    if (verifier) s->verify = verifier->new_scratch();
    if (locator) s->locate = locator->new_scratch();
    return s;
}

LoadedRuleset::Lease LoadedRuleset::lease() const {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!pool_.empty()) {
            std::unique_ptr<ThreadScratch> s = std::move(pool_.back());
            pool_.pop_back();
            return Lease(this, std::move(s));
        }
    }
    // Pool empty: create a new scratch space outside the lock. A scratch is only ever used by ONE scan at a time.
    return Lease(this, make_scratch());
}

void LoadedRuleset::give_back(std::unique_ptr<ThreadScratch> s) const {
    std::lock_guard<std::mutex> lock(mu_);
    if (pool_.size() < pool_max_) pool_.push_back(std::move(s));
    // else: destroyed here, when s goes out of scope
}

}  // namespace apg
