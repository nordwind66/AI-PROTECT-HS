// The engine object behind apg_context_t: configuration, the active rule set (atomically swappable), request
// parsing and the destroy/reload protocol. Everything here may throw apg::Error; the C ABI shim converts.
#pragma once

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "../core/config.h"
#include "../ruleset/loaded_ruleset.h"

namespace apg {

class Engine {
public:
    // Loads and fully verifies the initial rule set (throws Error on any problem).
    static std::unique_ptr<Engine> create(const Config& cfg);
    ~Engine();

    std::string scan_text(const uint8_t* utf8, size_t len, const char* source);
    std::string scan_json(const uint8_t* json, size_t len);
    std::string info_json();
    // Builds + verifies a new rule set completely, then swaps it in. On failure the old one stays active.
    void reload(const std::string& manifest_path_utf8);

    // Blocks until every call that started before this one has finished; later calls are refused.
    void close_and_wait();

private:
    explicit Engine(const Config& cfg) : cfg_(cfg) {}
    std::shared_ptr<const LoadedRuleset> current() const;

    class Inflight {
    public:
        explicit Inflight(Engine& e) : e_(e) {
            std::lock_guard<std::mutex> lock(e_.life_mu_);
            if (e_.closing_) throw Error(Status::InvalidArgument, "the context is being destroyed");
            ++e_.inflight_;
        }
        ~Inflight() {
            std::lock_guard<std::mutex> lock(e_.life_mu_);
            if (--e_.inflight_ == 0) e_.life_cv_.notify_all();
        }
        Inflight(const Inflight&) = delete;
        Inflight& operator=(const Inflight&) = delete;

    private:
        Engine& e_;
    };

    Config cfg_;
    mutable std::mutex swap_mu_;                       // protects current_
    std::shared_ptr<const LoadedRuleset> current_;
    std::mutex reload_mu_;                             // one reload at a time
    std::mutex life_mu_;
    std::condition_variable life_cv_;
    int inflight_ = 0;
    bool closing_ = false;
    std::string loaded_at_;
};

}  // namespace apg
