// Rule-set compiler: published SQLite snapshot -> Hyperscan databases + ruleset.meta.json + manifest.json.
//
//   dist/<os>/<arch>/<version>/
//       manifest.json            what was built, for which platform, hashes of everything
//       ruleset.meta.json        byte-identical copy of the published snapshot stored in SQLite
//       rules.<profile>.hsdb     serialised Hyperscan database of a normalisation profile; when the profile was split into
//                                shards (the default for big rule sets): rules.<profile>.01.hsdb, rules.<profile>.02.hsdb, ...
//       build_report.json        per-pattern outcome (native / prefilter / failed + exact error + provenance)
//
// How the Hyperscan databases are built (this is the slow part of a build, so it runs on all CPU threads):
//   1. every pattern is compiled ON ITS OWN, in parallel, with a deadline per attempt. A pattern that Hyperscan rejects
//      or that takes too long is retried in prefilter mode (PCRE2 then confirms every candidate) and finally with its
//      big counted repeats relaxed (`x{0,500}` -> `x{0,}`, a superset, also confirmed by PCRE2). What still fails is
//      isolated and listed in the report -- one bad expression never loses the rest of the rule set, and it does not
//      cost a recompilation of everything else.
//   2. the surviving patterns are spread over shards of similar compile cost; each shard is one hs_compile_multi() call
//      and the shards are compiled in parallel. The runtime scans every shard of a profile and merges the hits.
#pragma once

#include <functional>
#include <string>
#include <vector>

namespace apg {

struct CompileOptions {
    std::string db_path;
    std::string version;
    std::string out_dir = "dist";
    std::string backend = "hyperscan";       // hyperscan | pcre2_fallback
    std::string cpu_target = "generic";      // generic (portable) | host (tuned for this machine)
    bool force = false;                      // overwrite an existing output directory
    bool strict = false;                     // any isolated (failed) pattern makes the command fail
    bool verify_after_build = true;          // load the result back before publishing the directory
    int jobs = 0;                            // worker threads; 0 = one per CPU thread (at most 16)
    int shards = 0;                          // databases per profile; 0 = automatic (about one per worker)
    int pattern_timeout_s = 30;              // one compile attempt of one pattern may take at most this long
    int shard_timeout_s = 1800;              // one database shard may take at most this long (then it is split)
    unsigned relax_repeat = 32;              // last-resort prefilter form: counted repeats above this bound become {n,}; 0 = off
};

struct PatternOutcome {
    unsigned id = 0;
    std::string klass;                       // native | prefilter | failed
    bool downgraded = false;                 // static class native, but Hyperscan needed prefilter mode
    bool relaxed = false;                    // prefilter form with relaxed counted repeats
    std::string error;
    std::vector<std::string> provenance;     // source_id:source_key (path)
    std::vector<std::string> rules;          // rule ids that use the pattern
};

struct CompileReport {
    bool ok = false;
    std::string out_dir;                     // final directory
    std::string manifest_path;
    int total = 0, native = 0, prefilter = 0, failed = 0, downgraded = 0, relaxed = 0;
    int databases = 0;                       // .hsdb files written
    int jobs = 0;                            // worker threads used
    double elapsed_s = 0;
    std::vector<PatternOutcome> outcomes;
};

// Throws apg::Error on fatal problems (database unreadable, version not published, Hyperscan unavailable ...).
CompileReport compile_ruleset(const CompileOptions& opt, const std::function<void(const std::string&)>& log);

// Rewrites every counted repeat {m}, {m,} or {m,n} of a PCRE-style expression whose bounds exceed `cap` into {min(m,cap),}.
// The result matches a SUPERSET of the input, which is exactly what a prefilter may do. Escapes, character classes,
// \x{...} / \p{...} and \Q...\E are left alone. cap == 0 returns the input. *changed tells whether anything was rewritten.
std::string relax_repeats(const std::string& regex, unsigned cap, bool* changed);

// Worker threads abandoned because a Hyperscan call did not return within its deadline (process-wide). When this is not
// zero those threads may still be running: end the process with std::_Exit() instead of returning from main().
int compile_abandoned_workers();

}  // namespace apg
