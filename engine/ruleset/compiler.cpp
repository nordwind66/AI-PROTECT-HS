#include "compiler.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <map>
#include <memory>
#include <numeric>
#include <set>
#include <thread>

#include "../core/config.h"
#include "../core/fileio.h"
#include "../core/hs_backend.h"
#include "../core/json.h"
#include "../core/pcre2_set.h"
#include "../core/platform.h"
#include "../core/sha256.h"
#include "../storage/sqlite_store.h"
#include "job_pool.h"
#include "manifest.h"
#include "ruleset_model.h"

namespace apg {

namespace {

std::string utc_now_text() {
    const std::time_t t = std::time(nullptr);
    std::tm tmv;
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return std::string(buf);
}

std::string compiler_id() {
#if defined(__clang__)
    return std::string("clang ") + __clang_version__;
#elif defined(__GNUC__)
    return std::string("gcc ") + __VERSION__;
#elif defined(_MSC_VER)
    return "msvc " + std::to_string(_MSC_VER);
#else
    return "unknown";
#endif
}

Json jstr(const std::string& s) { return Json::make_string(s); }
Json jint(long long v) { return Json::make_int(v); }

Json ids_array(const std::vector<unsigned>& ids) {
    Json a = Json::make_array();
    for (unsigned id : ids) a.push_back(jint(id));
    return a;
}

std::string hex_u64(unsigned long long v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", v);
    return std::string(buf);
}

void must_write(const std::string& path, const std::string& data) {
    std::string err;
    if (!write_file_atomic(path, data, &err)) throw Error(Status::Database, err);
}

#ifdef APG_WITH_HYPERSCAN

typedef std::function<void(const std::string&)> LogFn;
typedef std::chrono::steady_clock Clock;

double seconds_since(const Clock::time_point& t) { return std::chrono::duration<double>(Clock::now() - t).count(); }

std::string fmt_duration(double s) {
    char buf[64];
    if (s < 60.0) {
        std::snprintf(buf, sizeof(buf), "%.1f s", s);
    } else if (s < 3600.0) {
        std::snprintf(buf, sizeof(buf), "%dm%02ds", static_cast<int>(s / 60.0), static_cast<int>(s) % 60);
    } else {
        std::snprintf(buf, sizeof(buf), "%dh%02dm", static_cast<int>(s / 3600.0), (static_cast<int>(s) / 60) % 60);
    }
    return std::string(buf);
}

int default_jobs() {
    const unsigned hc = std::thread::hardware_concurrency();
    if (hc == 0) return 1;
    return static_cast<int>(hc > 16u ? 16u : hc);
}

struct HsEntry {
    int idx = 0;                  // index into RuleSetData::patterns
    unsigned id = 0;              // pattern id = Hyperscan expression id
    std::string expr;             // expression handed to Hyperscan (the relaxed text for relaxed entries)
    unsigned flags = 0;
    bool prefilter = false;       // compiled with HS_FLAG_PREFILTER (static class, or after a downgrade)
    bool downgraded = false;      // static class native, Hyperscan needed prefilter mode
    bool relaxed = false;         // counted repeats were relaxed to keep the compilation tractable
    double cost_ms = 0;           // standalone compile time of the final form (balances the shards)
    size_t cost_bytes = 0;        // standalone database size of the final form
};

unsigned hs_flags_for(const PatternDef& p, bool prefilter) {
    unsigned f = HS_FLAG_UTF8 | HS_FLAG_SINGLEMATCH;
    if (p.flags & kFlagI) f |= HS_FLAG_CASELESS;
    if (p.flags & kFlagM) f |= HS_FLAG_MULTILINE;
    if (p.flags & kFlagS) f |= HS_FLAG_DOTALL;
    if (p.flags & kFlagU) f |= HS_FLAG_UCP;
    if (prefilter) f |= HS_FLAG_PREFILTER;
    return f;
}

// Everything the worker threads read. Immutable once the pool runs; owned through a shared_ptr because a worker that
// was abandoned (deadline) may outlive the function that created it.
struct HsEnv {
    std::vector<HsEntry> entries;
    hs_platform_info_t plat;
    unsigned relax_cap = 0;
};

// Job kind 0: compile ONE pattern on its own. attempt 0 = the entry as it is (native, or prefilter when its static class
// says so), 1 = prefilter mode, 2 = prefilter mode with relaxed counted repeats.
PoolResult probe_entry(const HsEnv& env, const PoolJob& job) {
    PoolResult r;
    const HsEntry& e = env.entries[job.index];
    std::string expr = e.expr;
    unsigned flags = e.flags;
    if (job.attempt >= 1) flags |= static_cast<unsigned>(HS_FLAG_PREFILTER);
    if (job.attempt >= 2) expr = relax_repeats(e.expr, env.relax_cap, nullptr);
    const Clock::time_point t0 = Clock::now();
    hs_database_t* db = nullptr;
    hs_compile_error_t* err = nullptr;
    const hs_error_t rc = hs_compile(expr.c_str(), flags, HS_MODE_BLOCK, &env.plat, &db, &err);
    r.ms = seconds_since(t0) * 1000.0;
    if (rc == HS_SUCCESS) {
        size_t sz = 0;
        if (hs_database_size(db, &sz) == HS_SUCCESS) r.bytes = sz;
        hs_free_database(db);
        r.ok = true;
    } else {
        r.error = (err != nullptr && err->message != nullptr) ? std::string(err->message) : std::string("Hyperscan compile error");
        if (err != nullptr) hs_free_compile_error(err);
    }
    return r;
}

// Job kind 1: compile the entries job.members (indexes into env.entries) into ONE database and serialise it.
PoolResult compile_shard(const HsEnv& env, const PoolJob& job) {
    PoolResult r;
    std::vector<const char*> ex;
    std::vector<unsigned> fl, ids;
    for (size_t m : job.members) {
        const HsEntry& e = env.entries[m];
        ex.push_back(e.expr.c_str());
        fl.push_back(e.flags);
        ids.push_back(e.id);
    }
    const Clock::time_point t0 = Clock::now();
    hs_database_t* db = nullptr;
    hs_compile_error_t* err = nullptr;
    const hs_error_t rc = hs_compile_multi(ex.data(), fl.data(), ids.data(), static_cast<unsigned>(ex.size()), HS_MODE_BLOCK,
                                           &env.plat, &db, &err);
    if (rc != HS_SUCCESS) {
        r.error = (err != nullptr && err->message != nullptr) ? std::string(err->message) : std::string("Hyperscan compile error");
        r.bad_index = err != nullptr ? err->expression : -1;
        if (err != nullptr) hs_free_compile_error(err);
        r.ms = seconds_since(t0) * 1000.0;
        return r;
    }
    char* bytes = nullptr;
    size_t blen = 0;
    const hs_error_t se = hs_serialize_database(db, &bytes, &blen);
    hs_free_database(db);
    r.ms = seconds_since(t0) * 1000.0;
    if (se != HS_SUCCESS || bytes == nullptr) {
        r.error = "hs_serialize_database failed";
        return r;
    }
    r.blob.assign(bytes, blen);
    std::free(bytes);
    r.bytes = blen;
    r.ok = true;
    return r;
}

struct ProbeState {
    bool done = false;
    bool ok = false;
    std::vector<int> plan;        // attempts still to make, in order (see compile_profile)
    size_t step = 0;              // index into plan of the attempt in flight
    signed char pcre = -1;        // can PCRE2 confirm candidates of this pattern?  -1 unknown, 0 no, 1 yes
    std::string pcre_why;
    std::string errors;           // what every failed attempt said
    std::string expr;             // final form
    unsigned flags = 0;
    bool prefilter = false;
    bool downgraded = false;
    bool relaxed = false;
    double ms = 0;
    size_t bytes = 0;
};

struct ShardOut {
    std::vector<HsEntry> entries;     // in the form they were compiled
    std::string blob;                 // serialised database
    double ms = 0;
};

unsigned min_pattern_id(const ShardOut& s) {
    unsigned m = 0xFFFFFFFFu;
    for (const HsEntry& e : s.entries) m = std::min(m, e.id);
    return m;
}

const char* attempt_label(int attempt, bool static_prefilter) {
    if (attempt == 0) return static_prefilter ? "prefilter" : "native";
    if (attempt == 1) return "prefilter";
    return "prefilter with relaxed repeats";
}

// Compiles all entries of one profile. On return `entries` holds the entries that made it into a database, `failures`
// has gained the isolated ones and `shards` the serialised databases.
void compile_profile(const RuleSetData& d, const std::string& profile, std::vector<HsEntry>& entries,
                     const hs_platform_info_t& plat, const CompileOptions& opt, int jobs, const LogFn& log,
                     std::map<unsigned, std::string>& failures, std::vector<ShardOut>& shards) {
    const size_t n = entries.size();
    if (n == 0) return;
    const unsigned cap = opt.relax_repeat;
    const int max_abandoned = std::max(4, jobs * 2);    // replacement workers that may be started for jobs that hit their deadline

    // ---- phase 1: every pattern on its own, in parallel ------------------------------------------------------------
    std::shared_ptr<HsEnv> env1 = std::make_shared<HsEnv>();
    env1->entries = entries;
    env1->plat = plat;
    env1->relax_cap = cap;
    std::vector<ProbeState> probe(n);
    for (size_t i = 0; i < n; ++i) {
        if (entries[i].prefilter) probe[i].pcre = 1;     // verified before the screening started
    }
    // PCRE2 must be able to confirm every prefilter candidate, otherwise a prefilter form is useless
    auto pcre2_can_verify = [&](size_t i) -> bool {
        ProbeState& p = probe[i];
        if (p.pcre < 0) {
            Pcre2Limits lim;
            Pcre2Set check(d, std::vector<int>{entries[i].idx}, lim);
            if (check.has(entries[i].idx)) {
                p.pcre = 1;
            } else {
                p.pcre = 0;
                p.pcre_why = check.failures().empty() ? std::string("unknown") : check.failures().front().second;
            }
        }
        return p.pcre == 1;
    };
    // The attempts of every pattern, in order (0 = as it is, 1 = prefilter mode, 2 = prefilter mode with relaxed repeats):
    //   normal pattern                            0, 1, 2
    //   pattern whose static class is prefilter   0, 2
    //   a counted repeat above 2 x the relax cap  2, 1   (compiling those natively in UTF-8 mode is hopeless: Hyperscan
    //                                                    answers "Pattern is too large", but only after a long time)
    // The step after a time-out is always 2: the same expression in another mode would most likely be as slow.
    std::vector<unsigned long long> weight(n, 0);       // expected compile cost: the slow patterns are started first
    size_t n_heavy = 0;
    for (size_t i = 0; i < n; ++i) {
        const HsEntry& e = entries[i];
        bool can_relax = false, heavy = false;
        if (cap > 0) {
            (void)relax_repeats(e.expr, cap, &can_relax);
            if (can_relax) (void)relax_repeats(e.expr, cap * 2u, &heavy);
        }
        weight[i] = repeat_weight(e.expr) + e.expr.size() / 16;
        std::vector<int>& plan_i = probe[i].plan;
        if (e.prefilter) {
            plan_i.push_back(0);
            if (can_relax) plan_i.push_back(2);
        } else if (heavy && pcre2_can_verify(i)) {
            plan_i.push_back(2);
            plan_i.push_back(1);
            ++n_heavy;
        } else {
            plan_i.push_back(0);
            plan_i.push_back(1);
            if (can_relax) plan_i.push_back(2);
        }
    }
    // Time limit of the attempt a pattern is on: attempts that a later relaxed attempt can still rescue get the short
    // limit, the last chance (and the relaxed attempt itself) the generous one.
    auto limit_for = [&](size_t i) -> double {
        const ProbeState& p = probe[i];
        if (p.plan[p.step] == 2) return opt.pattern_timeout_s;
        for (size_t k = p.step + 1; k < p.plan.size(); ++k) {
            if (p.plan[k] == 2) return opt.native_timeout_s;
        }
        return opt.pattern_timeout_s;
    };
    size_t finished = 0, n_native = 0, n_pre = 0, n_failed = 0, n_timeouts = 0;
    const Clock::time_point t1 = Clock::now();
    log(profile + ": screening " + std::to_string(n) + " patterns one by one on " + std::to_string(jobs) +
        " worker thread(s), limit " + std::to_string(opt.native_timeout_s) + " s for attempts that have a fallback, " +
        std::to_string(opt.pattern_timeout_s) + " s for the last chance" +
        (n_heavy > 0 ? "; " + std::to_string(n_heavy) + " pattern(s) with very large counted repeats start with the relaxed prefilter form"
                     : std::string()));
    {
        JobPool pool(jobs, [env1](const PoolJob& j) { return probe_entry(*env1, j); }, max_abandoned);

        // Patterns with big counted repeats and long expressions are the slow ones: start them first. Left for the end, a single
        // slow pattern (about 30 s) would run alone while the other workers are idle (seen on the first Linux run).
        std::vector<size_t> order(n);
        std::iota(order.begin(), order.end(), static_cast<size_t>(0));
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return weight[a] > weight[b]; });
        for (size_t i : order) {
            PoolJob j;
            j.kind = 0;
            j.index = i;
            j.attempt = probe[i].plan[0];
            j.timeout_s = limit_for(i);
            pool.submit(j);
        }

        // the attempt after the one that just failed, or -1 when nothing is left to try
        auto next_attempt = [&](size_t i, bool timed_out) -> int {
            ProbeState& p = probe[i];
            while (++p.step < p.plan.size()) {
                const int na = p.plan[p.step];
                if (timed_out && na != 2) continue;
                if (na >= 1 && !pcre2_can_verify(i)) {
                    p.errors += "prefilter mode is not usable because PCRE2 cannot compile the pattern (" + p.pcre_why + "); ";
                    return -1;
                }
                return na;
            }
            return -1;
        };
        auto on_result = [&](PoolResult& r) {
            const size_t i = r.job.index;
            ProbeState& p = probe[i];
            const HsEntry& e = entries[i];
            const int a = r.job.attempt;
            if (r.ok) {
                p.done = true;
                p.ok = true;
                p.ms = r.ms;
                p.bytes = r.bytes;
                p.relaxed = (a >= 2);
                p.prefilter = e.prefilter || a >= 1;
                p.downgraded = !e.prefilter && a >= 1;
                p.flags = e.flags | (a >= 1 ? static_cast<unsigned>(HS_FLAG_PREFILTER) : 0u);
                p.expr = (a >= 2) ? relax_repeats(e.expr, cap, nullptr) : e.expr;
                ++finished;
                if (p.prefilter) ++n_pre; else ++n_native;
                return;
            }
            if (r.skipped) {
                throw Error(Status::Limit, profile + ": no compile worker is left: " + std::to_string(pool.abandoned()) +
                                               " compile attempt(s) did not return within their time limit (" + std::to_string(opt.native_timeout_s) +
                                               " / " + std::to_string(opt.pattern_timeout_s) +
                                               " s) and their threads cannot be stopped. Raise --native-timeout / --pattern-timeout, lower --relax-repeat, "
                                               "or compile with fewer --jobs on a quieter machine");
            }
            if (r.timed_out) ++n_timeouts;
            p.errors += std::string(attempt_label(a, e.prefilter)) + ": " + r.error + "; ";
            const int nx = next_attempt(i, r.timed_out);
            if (nx >= 0) {
                PoolJob j;
                j.kind = 0;
                j.index = i;
                j.attempt = nx;
                j.timeout_s = limit_for(i);
                pool.submit(j);
                return;
            }
            p.done = true;
            p.ok = false;
            ++finished;
            ++n_failed;
        };
        auto on_tick = [&](const PoolStatus& s) {
            std::string line = profile + " screening: " + std::to_string(finished) + "/" + std::to_string(n) + " patterns done (" +
                               std::to_string(n_native) + " native, " + std::to_string(n_pre) + " prefilter, " +
                               std::to_string(n_failed) + " isolated), " + std::to_string(s.running) + " running, elapsed " +
                               fmt_duration(seconds_since(t1));
            if (s.running > 0 && s.oldest_s >= 10.0) {
                line += "; longest right now: pattern " + std::to_string(entries[s.oldest.index].id) + " for " +
                        fmt_duration(s.oldest_s);
            }
            log(line);
        };
        pool.run(on_result, on_tick, 5.0);
    }

    std::vector<HsEntry> good;
    good.reserve(n);
    size_t n_downgraded = 0, n_relaxed = 0;
    for (size_t i = 0; i < n; ++i) {
        const ProbeState& p = probe[i];
        HsEntry e = entries[i];
        if (!p.ok) {
            std::string msg = p.errors;
            while (!msg.empty() && (msg.back() == ' ' || msg.back() == ';')) msg.pop_back();
            failures[e.id] = msg.empty() ? std::string("Hyperscan could not compile this pattern") : msg;
            continue;
        }
        e.expr = p.expr;
        e.flags = p.flags;
        e.prefilter = p.prefilter;
        e.downgraded = p.downgraded;
        e.relaxed = p.relaxed;
        e.cost_ms = p.ms;
        e.cost_bytes = p.bytes;
        if (e.downgraded) ++n_downgraded;
        if (e.relaxed) ++n_relaxed;
        good.push_back(std::move(e));
    }
    log(profile + ": screening finished in " + fmt_duration(seconds_since(t1)) + ": " + std::to_string(n_native) + " native, " +
        std::to_string(n_pre) + " prefilter (" + std::to_string(n_downgraded) + " downgraded from native, " +
        std::to_string(n_relaxed) + " with relaxed repeats), " + std::to_string(n_failed) + " isolated" +
        (n_timeouts > 0 ? ", " + std::to_string(n_timeouts) + " attempt(s) hit the time limit" : std::string()));
    {
        size_t shown = 0;
        for (size_t i = 0; i < n && shown < 10; ++i) {
            if (probe[i].ok) continue;
            std::string msg = failures[entries[i].id];
            if (msg.size() > 200) msg = msg.substr(0, 200) + "...";
            log("  isolated pattern " + std::to_string(entries[i].id) + ": " + msg);
            ++shown;
        }
        if (n_failed > shown) log("  ... and " + std::to_string(n_failed - shown) + " more (all of them are listed in build_report.json)");
    }
    entries.clear();
    if (good.empty()) return;

    // ---- phase 2: shards of similar cost, one hs_compile_multi() per shard, in parallel ------------------------------
    size_t shard_count;
    if (opt.shards > 0) {
        shard_count = static_cast<size_t>(opt.shards);
    } else {
        shard_count = std::min(static_cast<size_t>(jobs), (good.size() + 47) / 48);
    }
    if (shard_count < 1) shard_count = 1;
    if (shard_count > good.size()) shard_count = good.size();

    auto cost_of = [&good](size_t i) { return std::max(1.0, good[i].cost_ms) + static_cast<double>(good[i].cost_bytes) / 4096.0; };
    std::vector<size_t> by_cost(good.size());
    std::iota(by_cost.begin(), by_cost.end(), static_cast<size_t>(0));
    std::sort(by_cost.begin(), by_cost.end(), [&](size_t a, size_t b) {
        const double ca = cost_of(a), cb = cost_of(b);
        if (ca != cb) return ca > cb;
        return good[a].id < good[b].id;
    });
    std::vector<std::vector<size_t>> plan(shard_count);
    std::vector<double> load(shard_count, 0.0);
    for (size_t i : by_cost) {                       // longest processing time first: greedy balancing
        size_t best = 0;
        for (size_t s = 1; s < shard_count; ++s) {
            if (load[s] < load[best]) best = s;
        }
        plan[best].push_back(i);
        load[best] += cost_of(i);
    }
    for (std::vector<size_t>& m : plan) std::sort(m.begin(), m.end());

    std::shared_ptr<HsEnv> env2 = std::make_shared<HsEnv>();
    env2->entries = good;
    env2->plat = plat;
    env2->relax_cap = cap;
    const int workers2 = static_cast<int>(std::min(static_cast<size_t>(jobs), shard_count));
    log(profile + ": compiling " + std::to_string(good.size()) + " patterns as " + std::to_string(shard_count) +
        " database shard(s) on " + std::to_string(workers2) + " worker thread(s)");
    const Clock::time_point t2 = Clock::now();
    size_t shards_done = 0;
    {
        JobPool pool2(workers2, [env2](const PoolJob& j) { return compile_shard(*env2, j); }, max_abandoned);
        std::vector<size_t> sorder(shard_count);
        std::iota(sorder.begin(), sorder.end(), static_cast<size_t>(0));
        std::sort(sorder.begin(), sorder.end(), [&](size_t a, size_t b) { return load[a] > load[b]; });
        for (size_t s : sorder) {
            if (plan[s].empty()) continue;
            PoolJob j;
            j.kind = 1;
            j.index = s;
            j.members = plan[s];
            j.timeout_s = opt.shard_timeout_s;
            pool2.submit(j);
        }
        auto on_result2 = [&](PoolResult& r) {
            std::vector<size_t> mem = r.job.members;
            if (r.ok) {
                ShardOut so;
                for (size_t m : mem) so.entries.push_back(good[m]);
                so.blob = std::move(r.blob);
                so.ms = r.ms;
                log(profile + ": database finished: " + std::to_string(mem.size()) + " patterns, " +
                    std::to_string(so.blob.size() / 1024) + " KiB, " + fmt_duration(r.ms / 1000.0));
                shards.push_back(std::move(so));
                ++shards_done;
                return;
            }
            if (r.skipped) throw Error(Status::Internal, "no worker thread left to compile a database shard: " + r.error);
            if (r.timed_out) {
                if (mem.size() > 1) {
                    const size_t half = mem.size() / 2;
                    log(profile + ": a database of " + std::to_string(mem.size()) + " patterns did not finish within " +
                        std::to_string(opt.shard_timeout_s) + " s: splitting it in two");
                    PoolJob a, b;
                    a.kind = b.kind = 1;
                    a.index = b.index = r.job.index;
                    a.timeout_s = b.timeout_s = opt.shard_timeout_s;
                    a.members.assign(mem.begin(), mem.begin() + static_cast<std::ptrdiff_t>(half));
                    b.members.assign(mem.begin() + static_cast<std::ptrdiff_t>(half), mem.end());
                    pool2.submit(a);
                    pool2.submit(b);
                    return;
                }
                failures[good[mem[0]].id] = "compiling this pattern inside a database did not finish within " +
                                            std::to_string(opt.shard_timeout_s) + " s";
                return;
            }
            if (r.bad_index >= 0 && static_cast<size_t>(r.bad_index) < mem.size()) {
                const size_t victim = mem[static_cast<size_t>(r.bad_index)];
                failures[good[victim].id] = "rejected while compiling together with other patterns: " + r.error;
                log(profile + ": pattern " + std::to_string(good[victim].id) + " was rejected inside a database (" + r.error +
                    "): isolated, the rest is compiled again");
                mem.erase(mem.begin() + r.bad_index);
                if (!mem.empty()) {
                    PoolJob j;
                    j.kind = 1;
                    j.index = r.job.index;
                    j.members = mem;
                    j.timeout_s = opt.shard_timeout_s;
                    pool2.submit(j);
                }
                return;
            }
            throw Error(Status::Database, "Hyperscan could not compile a database shard of profile " + profile + ": " + r.error);
        };
        auto on_tick2 = [&](const PoolStatus& s) {
            log(profile + " compiling databases: " + std::to_string(shards_done) + " finished, " + std::to_string(s.running) +
                " running, " + std::to_string(s.queued) + " waiting, elapsed " + fmt_duration(seconds_since(t2)));
        };
        pool2.run(on_result2, on_tick2, 10.0);
    }
    std::sort(shards.begin(), shards.end(), [](const ShardOut& a, const ShardOut& b) { return min_pattern_id(a) < min_pattern_id(b); });
    for (const ShardOut& s : shards) {
        for (const HsEntry& e : s.entries) entries.push_back(e);
    }
    log(profile + ": " + std::to_string(shards.size()) + " database(s) compiled in " + fmt_duration(seconds_since(t2)));
}

#endif  // APG_WITH_HYPERSCAN

}  // namespace

// ---- relax_repeats / repeat_weight ----------------------------------------------------------------------------------------
// One scanner for both jobs: rewriting big counted repeats (cap > 0) and measuring them (weight != nullptr).
static std::string scan_repeats(const std::string& rx, unsigned cap, bool* changed, unsigned long long* weight) {
    if (changed != nullptr) *changed = false;
    if (weight != nullptr) *weight = 0;
    if (cap == 0 && weight == nullptr) return rx;
    std::string out;
    out.reserve(rx.size());
    const size_t n = rx.size();
    size_t i = 0;
    bool in_class = false;
    while (i < n) {
        const char c = rx[i];
        if (c == '\\') {
            if (!in_class && i + 1 < n && rx[i + 1] == 'Q') {                 // \Q ... \E: literal text
                const size_t e = rx.find("\\E", i + 2);
                const size_t stop = (e == std::string::npos) ? n : e + 2;
                out.append(rx, i, stop - i);
                i = stop;
                continue;
            }
            out.push_back(c);
            ++i;
            if (i < n) {
                const char d = rx[i];
                out.push_back(d);
                ++i;
                // \x{2000}, \p{L}, \N{U+..}, \o{..}, \g{..}, \k{..}: the braces belong to the escape
                if ((d == 'x' || d == 'p' || d == 'P' || d == 'N' || d == 'o' || d == 'g' || d == 'k') && i < n && rx[i] == '{') {
                    const size_t e = rx.find('}', i);
                    const size_t stop = (e == std::string::npos) ? n : e + 1;
                    out.append(rx, i, stop - i);
                    i = stop;
                }
            }
            continue;
        }
        if (in_class) {
            if (c == '[' && i + 1 < n && rx[i + 1] == ':') {                  // [:alpha:] inside a class
                const size_t e = rx.find(":]", i + 2);
                if (e != std::string::npos) {
                    out.append(rx, i, e + 2 - i);
                    i = e + 2;
                    continue;
                }
            }
            if (c == ']') in_class = false;
            out.push_back(c);
            ++i;
            continue;
        }
        if (c == '[') {
            in_class = true;
            out.push_back(c);
            ++i;
            if (i < n && rx[i] == '^') {
                out.push_back('^');
                ++i;
            }
            if (i < n && rx[i] == ']') {                                       // a leading ] is a literal
                out.push_back(']');
                ++i;
            }
            continue;
        }
        if (c == '(' && i + 2 < n && rx[i + 1] == '?' && rx[i + 2] == '#') {  // (?# comment )
            const size_t e = rx.find(')', i);
            const size_t stop = (e == std::string::npos) ? n : e + 1;
            out.append(rx, i, stop - i);
            i = stop;
            continue;
        }
        if (c == '{') {
            size_t j = i + 1;
            unsigned long long lo = 0, hi = 0;
            bool has_lo = false, comma = false, has_hi = false;
            while (j < n && rx[j] >= '0' && rx[j] <= '9') {
                lo = lo * 10 + static_cast<unsigned long long>(rx[j] - '0');
                if (lo > 1000000000ULL) lo = 1000000000ULL;
                has_lo = true;
                ++j;
            }
            if (has_lo && j < n && rx[j] == ',') {
                comma = true;
                ++j;
                while (j < n && rx[j] >= '0' && rx[j] <= '9') {
                    hi = hi * 10 + static_cast<unsigned long long>(rx[j] - '0');
                    if (hi > 1000000000ULL) hi = 1000000000ULL;
                    has_hi = true;
                    ++j;
                }
            }
            if (has_lo && j < n && rx[j] == '}') {                             // a counted repeat {m} {m,} {m,n}
                const unsigned long long upper = has_hi ? hi : (comma ? lo + 64 : lo);     // {m,} counts as a bit more than m
                if (weight != nullptr) *weight += upper < 4000ULL ? upper : 4000ULL;
                const bool too_big = cap > 0 && (lo > cap || (comma && has_hi && hi > cap));
                if (too_big) {
                    const unsigned long long keep = lo < cap ? lo : static_cast<unsigned long long>(cap);
                    out += "{" + std::to_string(keep) + ",}";
                    if (changed != nullptr) *changed = true;
                } else {
                    out.append(rx, i, j + 1 - i);
                }
                i = j + 1;
                continue;
            }
            // not a quantifier: a literal brace
        }
        out.push_back(c);
        ++i;
    }
    return out;
}

std::string relax_repeats(const std::string& rx, unsigned cap, bool* changed) {
    return scan_repeats(rx, cap, changed, nullptr);
}

unsigned long long repeat_weight(const std::string& rx) {
    unsigned long long w = 0;
    (void)scan_repeats(rx, 0, nullptr, &w);
    return w;
}

int compile_abandoned_workers() { return pool_abandoned_total(); }

// ---- compile_ruleset --------------------------------------------------------------------------------------------------
CompileReport compile_ruleset(const CompileOptions& opt, const std::function<void(const std::string&)>& log) {
    if (opt.backend != "hyperscan" && opt.backend != "pcre2_fallback") {
        throw Error(Status::Config, "--backend must be hyperscan or pcre2_fallback");
    }
    if (opt.cpu_target != "generic" && opt.cpu_target != "host") throw Error(Status::Config, "--cpu-target must be generic or host");
    if (opt.jobs < 0 || opt.shards < 0 || opt.native_timeout_s < 1 || opt.pattern_timeout_s < 1 || opt.shard_timeout_s < 1) {
        throw Error(Status::Config, "--jobs and --shards must not be negative; --native-timeout, --pattern-timeout and --shard-timeout must be at least 1 second");
    }
#ifndef APG_WITH_HYPERSCAN
    if (opt.backend == "hyperscan") {
        throw Error(Status::Platform, "this ai-prompt-guard was built without Hyperscan; use --backend pcre2_fallback "
                                      "or rebuild with -DAPG_WITH_HYPERSCAN=ON");
    }
#endif
    const std::chrono::steady_clock::time_point t_start = std::chrono::steady_clock::now();
    SqliteStore store(opt.db_path);
    const SnapshotRow snap = store.load_published_snapshot(opt.version);
    log("snapshot " + snap.version + ": sha256 " + snap.sha256_recorded.substr(0, 16) + "..., " + std::to_string(snap.rule_count) +
        " rules, " + std::to_string(snap.pattern_count) + " patterns");
    std::shared_ptr<RuleSetData> data = parse_snapshot(snap.body);

    const std::string final_dir = path_join(path_join(path_join(opt.out_dir, APG_OS_NAME), APG_ARCH_NAME), opt.version);
    const std::string tmp_dir = final_dir + ".building";
    if (path_exists(final_dir) && !opt.force) {
        throw Error(Status::Config, "output directory " + final_dir + " already exists (use --force to replace it)");
    }
    std::string err;
    if (path_exists(tmp_dir) && !remove_all_path(tmp_dir, &err)) throw Error(Status::Database, err);
    if (!make_dirs(tmp_dir, &err)) throw Error(Status::Database, err);

    CompileReport report;
    report.total = static_cast<int>(data->patterns.size());
    std::map<unsigned, std::string> failures;
    std::map<unsigned, bool> downgraded;
    std::map<unsigned, bool> is_prefilter;
    std::map<unsigned, bool> relaxed;
    Json databases = Json::make_array();
    std::string hs_version_text;
    std::string cpu_features_text = "0x0";
    long long tune_value = 0;

    if (opt.backend == "hyperscan") {
#ifdef APG_WITH_HYPERSCAN
        if (hs_valid_platform() != HS_SUCCESS) {
            throw Error(Status::Platform, "this CPU does not support Hyperscan (SSSE3 required)");
        }
        hs_version_text = HsBackend::library_version();
        hs_platform_info_t plat;
        if (hs_populate_platform(&plat) != HS_SUCCESS) throw Error(Status::Platform, "hs_populate_platform failed");
        if (opt.cpu_target == "generic") {
            plat.tune = HS_TUNE_FAMILY_GENERIC;
            plat.cpu_features = 0;
        }
        cpu_features_text = hex_u64(static_cast<unsigned long long>(plat.cpu_features));
        tune_value = static_cast<long long>(plat.tune);
        log("Hyperscan " + hs_version_text + ", cpu-target " + opt.cpu_target + " (features " + cpu_features_text + ")");
        const int jobs = opt.jobs > 0 ? opt.jobs : default_jobs();
        report.jobs = jobs;
        log("parallel build: " + std::to_string(jobs) + " worker thread(s), " +
            (opt.shards > 0 ? std::to_string(opt.shards) + " database shard(s) per profile" : std::string("automatic number of database shards")) +
            ", repeat relaxation " + (opt.relax_repeat > 0 ? "above " + std::to_string(opt.relax_repeat) : std::string("off")) +
            " (the Hyperscan compiler is assumed to be re-entrant; --jobs 1 builds strictly sequentially)");

        // PCRE2 must be able to compile every pattern that will need confirmation. Native patterns are
        // checked lazily (only if Hyperscan rejects them).
        for (size_t pi = 0; pi < data->profiles.size(); ++pi) {
            std::vector<HsEntry> entries;
            for (size_t i = 0; i < data->patterns.size(); ++i) {
                const PatternDef& p = data->patterns[i];
                if (static_cast<size_t>(p.profile) != pi) continue;
                if (p.regex.find('\0') != std::string::npos) {
                    failures[p.id] = "pattern contains a NUL byte";
                    continue;
                }
                HsEntry e;
                e.idx = static_cast<int>(i);
                e.expr = p.regex;
                e.id = p.id;
                e.prefilter = (p.cls == PatternClass::Prefilter);
                e.flags = hs_flags_for(p, e.prefilter);
                entries.push_back(e);
            }
            // verify the prefilter class with PCRE2 first
            {
                std::vector<int> pf;
                for (const HsEntry& e : entries) {
                    if (e.prefilter) pf.push_back(e.idx);
                }
                if (!pf.empty()) {
                    Pcre2Limits lim;
                    Pcre2Set check(*data, pf, lim);
                    for (const auto& f : check.failures()) {
                        failures[data->patterns[static_cast<size_t>(f.first)].id] = "PCRE2 cannot compile this prefilter pattern: " + f.second;
                    }
                    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                                 [&](const HsEntry& e) { return failures.count(e.id) != 0; }),
                                  entries.end());
                }
            }
            if (entries.empty()) continue;
            std::vector<ShardOut> shards;
            compile_profile(*data, data->profiles[pi].name, entries, plat, opt, jobs, log, failures, shards);
            if (shards.empty()) continue;
            const bool single = shards.size() == 1;
            for (size_t k = 0; k < shards.size(); ++k) {
                const ShardOut& so = shards[k];
                char suffix[16] = {0};
                if (!single) std::snprintf(suffix, sizeof(suffix), ".%02d", static_cast<int>(k + 1));
                const std::string fname = "rules." + data->profiles[pi].name + suffix + ".hsdb";
                must_write(path_join(tmp_dir, fname), so.blob);
                std::vector<unsigned> nat, pre;
                for (const HsEntry& e : so.entries) {
                    (e.prefilter ? pre : nat).push_back(e.id);
                    downgraded[e.id] = e.downgraded;
                    is_prefilter[e.id] = e.prefilter;
                    relaxed[e.id] = e.relaxed;
                }
                std::sort(nat.begin(), nat.end());
                std::sort(pre.begin(), pre.end());
                Json dj = Json::make_object();
                dj.set("profile", jstr(data->profiles[pi].name));
                dj.set("path", jstr(fname));
                dj.set("sha256", jstr(sha256_hex(so.blob)));
                dj.set("bytes", jint(static_cast<long long>(so.blob.size())));
                dj.set("native_ids", ids_array(nat));
                dj.set("prefilter_ids", ids_array(pre));
                databases.push_back(dj);
                ++report.databases;
                log("wrote " + fname + ": " + std::to_string(nat.size()) + " native + " + std::to_string(pre.size()) +
                    " prefilter patterns, " + std::to_string(so.blob.size() / 1024) + " KiB");
            }
        }
#endif
    } else {  // pcre2_fallback: nothing is pre-compiled; verify that PCRE2 accepts every pattern
        Pcre2Limits lim;
        std::vector<int> all;
        for (size_t i = 0; i < data->patterns.size(); ++i) all.push_back(static_cast<int>(i));
        Pcre2Set check(*data, all, lim);
        for (const auto& f : check.failures()) failures[data->patterns[static_cast<size_t>(f.first)].id] = f.second;
        for (const PatternDef& p : data->patterns) {
            is_prefilter[p.id] = false;
            downgraded[p.id] = false;
            relaxed[p.id] = false;
        }
        log("pcre2_fallback backend: PCRE2 " + Pcre2Set::version());
    }

    // ---- metadata copy, report, manifest ----------------------------------------------------------------------------
    must_write(path_join(tmp_dir, "ruleset.meta.json"), snap.body);
    std::vector<unsigned> failed_ids;
    for (const auto& kv : failures) failed_ids.push_back(kv.first);
    std::map<uint32_t, std::vector<std::string>> rules_of_pattern;
    for (const RuleDef& r : data->rules) {
        for (const LeafDef& lf : r.leaves) rules_of_pattern[data->patterns[static_cast<size_t>(lf.pattern)].id].push_back(r.id);
    }
    Json report_patterns = Json::make_array();
    for (const PatternDef& p : data->patterns) {
        PatternOutcome o;
        o.id = p.id;
        const bool failed = failures.count(p.id) != 0;
        o.klass = failed ? "failed" : (is_prefilter[p.id] ? "prefilter" : "native");
        o.downgraded = !failed && downgraded[p.id];
        o.relaxed = !failed && relaxed[p.id];
        if (failed) {
            o.error = failures[p.id];
            o.provenance = store.provenance_of_pattern(p.id);
            auto it = rules_of_pattern.find(p.id);
            if (it != rules_of_pattern.end()) o.rules = it->second;
            ++report.failed;
        } else if (is_prefilter[p.id]) {
            ++report.prefilter;
        } else {
            ++report.native;
        }
        if (o.downgraded) ++report.downgraded;
        if (o.relaxed) ++report.relaxed;
        Json pj = Json::make_object();
        pj.set("id", jint(p.id));
        pj.set("class", jstr(o.klass == "native" ? "hs_native" : o.klass == "prefilter" ? "hs_prefilter_pcre2" : "unsupported"));
        pj.set("flags", jstr(p.flag_text));
        pj.set("profile", jstr(data->profiles[static_cast<size_t>(p.profile)].name));
        if (o.downgraded) pj.set("downgraded_from_native", Json::make_bool(true));
        if (o.relaxed) pj.set("relaxed_repeats", Json::make_bool(true));
        if (failed) {
            pj.set("error", jstr(o.error));
            Json prov = Json::make_array();
            for (const std::string& s : o.provenance) prov.push_back(jstr(s));
            pj.set("provenance", prov);
            Json ru = Json::make_array();
            for (const std::string& s : o.rules) ru.push_back(jstr(s));
            pj.set("rules", ru);
            pj.set("regex", jstr(p.regex));
            log("FAILED pattern " + std::to_string(p.id) + ": " + o.error);
        }
        report_patterns.push_back(pj);
        report.outcomes.push_back(o);
    }
    report.elapsed_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    Json rep = Json::make_object();
    rep.set("kind", jstr("apg-build-report"));
    rep.set("ruleset_version", jstr(data->version));
    rep.set("total", jint(report.total));
    rep.set("native", jint(report.native));
    rep.set("prefilter", jint(report.prefilter));
    rep.set("failed", jint(report.failed));
    rep.set("downgraded_to_prefilter", jint(report.downgraded));
    rep.set("relaxed_repeats", jint(report.relaxed));
    Json stats = Json::make_object();
    stats.set("jobs", jint(report.jobs));
    stats.set("databases", jint(report.databases));
    stats.set("native_timeout_s", jint(opt.native_timeout_s));
    stats.set("pattern_timeout_s", jint(opt.pattern_timeout_s));
    stats.set("shard_timeout_s", jint(opt.shard_timeout_s));
    stats.set("relax_repeat", jint(static_cast<long long>(opt.relax_repeat)));
    stats.set("elapsed_s", Json::make_double(report.elapsed_s));
    rep.set("build_stats", stats);
    rep.set("patterns", report_patterns);
    must_write(path_join(tmp_dir, "build_report.json"), json_dump_pretty(rep));

    Json m = Json::make_object();
    m.set("kind", jstr("apg-manifest"));
    m.set("manifest_version", jint(kManifestVersion));
    m.set("status", jstr(failed_ids.empty() ? "ok" : "partial"));
    Json eng = Json::make_object();
    eng.set("engine_version", jstr(APG_ENGINE_VERSION));
    eng.set("abi_version", jint(kAbiVersion));
    eng.set("norm_tables_version", jint(kNormTablesVersion));
    m.set("engine", eng);
    Json rs = Json::make_object();
    rs.set("version", jstr(data->version));
    rs.set("content_digest", jstr(data->content_digest));
    rs.set("snapshot_sha256", jstr(snap.sha256_recorded));
    rs.set("rule_count", jint(static_cast<long long>(data->rules.size())));
    rs.set("pattern_count", jint(static_cast<long long>(data->patterns.size())));
    m.set("ruleset", rs);
    Json tg = Json::make_object();
    tg.set("os", jstr(APG_OS_NAME));
    tg.set("arch", jstr(APG_ARCH_NAME));
    tg.set("backend", jstr(opt.backend));
    tg.set("hyperscan_version", jstr(hs_version_text));
    tg.set("pcre2_version", jstr(Pcre2Set::version()));
    tg.set("cpu_target", jstr(opt.cpu_target));
    tg.set("cpu_features", jstr(cpu_features_text));
    tg.set("tune", jint(tune_value));
    tg.set("compiler", jstr(compiler_id()));
    m.set("target", tg);
    Json files = Json::make_object();
    Json meta = Json::make_object();
    meta.set("path", jstr("ruleset.meta.json"));
    meta.set("sha256", jstr(snap.sha256_recorded));
    meta.set("bytes", jint(static_cast<long long>(snap.body.size())));
    files.set("meta", meta);
    files.set("databases", databases);
    m.set("files", files);
    Json pats = Json::make_object();
    pats.set("total", jint(report.total));
    pats.set("native", jint(report.native));
    pats.set("prefilter", jint(report.prefilter));
    pats.set("failed", jint(report.failed));
    pats.set("failed_ids", ids_array(failed_ids));
    m.set("patterns", pats);
    m.set("built_at", jstr(utc_now_text()));
    m.set("build_hash", jstr(manifest_build_hash(m)));
    must_write(path_join(tmp_dir, "manifest.json"), json_dump_pretty(m));

    // ---- self test: the artifacts must load on THIS machine --------------------------------------------------------
    if (opt.verify_after_build) {
        Config cfg;
        cfg.manifest_path = path_join(tmp_dir, "manifest.json");
        cfg.verify_ruleset = true;
        (void)load_ruleset(cfg.manifest_path, cfg);
        log("self-test: the compiled rule set loads and verifies on this machine");
    }
    if (opt.strict && !failed_ids.empty()) {
        std::string e2;
        remove_all_path(tmp_dir, &e2);
        throw Error(Status::Database, std::to_string(failed_ids.size()) + " pattern(s) could not be compiled (--strict); "
                                      "nothing was written. Re-run without --strict to isolate them.");
    }
    if (path_exists(final_dir) && !remove_all_path(final_dir, &err)) throw Error(Status::Database, err);
    if (!make_dirs(path_dir(final_dir), &err)) throw Error(Status::Database, err);
    if (!rename_path(tmp_dir, final_dir, &err)) throw Error(Status::Database, err);
    report.out_dir = final_dir;
    report.manifest_path = path_join(final_dir, "manifest.json");
    report.ok = true;
    return report;
}

}  // namespace apg
