#include "manifest.h"

#include <algorithm>
#include <set>

#include "../core/fileio.h"
#include "../core/hs_backend.h"
#include "../core/pcre_backend.h"
#include "../core/platform.h"
#include "../core/sha256.h"

namespace apg {

namespace {

[[noreturn]] void bad(const std::string& msg) { throw Error(Status::Database, msg); }

const Json& need(const Json& obj, const char* key, const char* where) {
    const Json* v = obj.get(key);
    if (v == nullptr) bad(std::string(where) + ": missing key '" + key + "'");
    return *v;
}

std::string read_checked(const std::string& path, size_t max_bytes) {
    std::string data, err;
    if (!read_file(path, &data, &err, max_bytes)) bad(err);
    return data;
}

}  // namespace

std::string resolve_inside(const std::string& base_dir, const std::string& relative) {
    if (relative.empty() || relative[0] == '/' || relative[0] == '\\' || relative.find(':') != std::string::npos ||
        relative.find("..") != std::string::npos) {
        bad("manifest file reference '" + relative + "' must be a relative path inside the manifest directory");
    }
    return path_join(base_dir, relative);
}

std::string manifest_build_hash(const Json& manifest) {
    Json copy = Json::make_object();
    for (const auto& kv : manifest.members()) {
        if (kv.first != "build_hash") copy.set(kv.first, kv.second);
    }
    return sha256_hex(json_dump_canonical(copy));
}

std::shared_ptr<LoadedRuleset> load_ruleset(const std::string& manifest_path_in, const Config& cfg) {
    std::string manifest_path = manifest_path_in;
    if (!path_exists(manifest_path)) {
        throw Error(Status::Config, "manifest_path '" + manifest_path + "' does not exist");
    }
    // ---- 0. active-pointer indirection -----------------------------------------------------------------
    {
        const Json first = Json::parse(read_checked(manifest_path, 16u << 20));
        const Json* kind = first.get("kind");
        if (kind != nullptr && kind->is_string() && kind->as_string() == "apg-active-pointer") {
            const std::string rel = need(first, "manifest", "active pointer").as_string();
            const std::string target = resolve_inside(path_dir(manifest_path), rel);
            const Json* want = first.get("manifest_sha256");
            if (want != nullptr && want->is_string()) {
                std::string have, err;
                if (!sha256_file(target, &have, &err)) bad(err);
                if (have != want->as_string()) bad("active pointer: manifest sha256 does not match (pointer is stale)");
            }
            manifest_path = target;
        }
    }
    const std::string base_dir = path_dir(manifest_path);

    // ---- 1. manifest -----------------------------------------------------------------------------------
    Json m;
    try {
        m = Json::parse(read_checked(manifest_path, 16u << 20));
    } catch (const Error& e) {
        bad(std::string("manifest.json: ") + e.what());
    }
    if (need(m, "kind", "manifest").as_string() != "apg-manifest") bad("not an apg-manifest document");
    if (need(m, "manifest_version", "manifest").as_int() != kManifestVersion) {
        throw Error(Status::Version, "manifest version " + std::to_string(need(m, "manifest_version", "manifest").as_int()) +
                                         " is not supported by this engine");
    }
    if (need(m, "build_hash", "manifest").as_string() != manifest_build_hash(m)) {
        bad("manifest build_hash does not match its content (the manifest was modified)");
    }
    const Json& eng = need(m, "engine", "manifest");
    if ((static_cast<uint32_t>(need(eng, "abi_version", "engine").as_int()) >> 16) != (kAbiVersion >> 16)) {
        throw Error(Status::Version, "rule set was built for another engine ABI major version");
    }
    if (need(eng, "norm_tables_version", "engine").as_int() != static_cast<int64_t>(kNormTablesVersion)) {
        throw Error(Status::Version, "rule set was built with other normalisation tables");
    }
    const Json& tgt = need(m, "target", "manifest");
    if (need(tgt, "os", "target").as_string() != APG_OS_NAME || need(tgt, "arch", "target").as_string() != APG_ARCH_NAME) {
        throw Error(Status::Platform, "rule set was compiled for " + need(tgt, "os", "target").as_string() + "/" +
                                          need(tgt, "arch", "target").as_string() + " but this process is " APG_OS_NAME "/" APG_ARCH_NAME);
    }
    const std::string backend_name = need(tgt, "backend", "target").as_string();
    const Json& rsj = need(m, "ruleset", "manifest");
    const Json& files = need(m, "files", "manifest");

    // ---- 2. snapshot ----------------------------------------------------------------------------------------
    const Json& meta = need(files, "meta", "files");
    const std::string meta_path = resolve_inside(base_dir, need(meta, "path", "files.meta").as_string());
    const std::string meta_bytes = read_checked(meta_path, 256u << 20);
    const std::string meta_sha = sha256_hex(meta_bytes);
    if (meta_sha != need(meta, "sha256", "files.meta").as_string() ||
        meta_sha != need(rsj, "snapshot_sha256", "ruleset").as_string()) {
        bad("ruleset metadata file does not match the sha256 recorded in the manifest");
    }
    std::shared_ptr<RuleSetData> data = parse_snapshot(meta_bytes);
    if (data->version != need(rsj, "version", "ruleset").as_string() ||
        data->content_digest != need(rsj, "content_digest", "ruleset").as_string()) {
        bad("manifest and ruleset metadata disagree about the rule-set version / content digest");
    }

    std::unique_ptr<LoadedRuleset> rs(new LoadedRuleset(cfg.limits.scratch_pool_max));
    rs->data = data;
    ManifestInfo& info = rs->info;
    info.manifest_path = manifest_path;
    info.ruleset_version = data->version;
    info.content_digest = data->content_digest;
    info.snapshot_sha256 = meta_sha;
    info.backend_name = backend_name;
    info.os = need(tgt, "os", "target").as_string();
    info.arch = need(tgt, "arch", "target").as_string();
    if (const Json* v = tgt.get("cpu_target")) info.cpu_target = v->as_string();
    if (const Json* v = tgt.get("hyperscan_version")) info.hs_version = v->as_string();
    if (const Json* v = m.get("built_at")) info.built_at = v->as_string();
    info.pcre2_version = Pcre2Set::version();
    info.rule_count = static_cast<int>(data->rules.size());
    info.pattern_count = static_cast<int>(data->patterns.size());

    // ---- 3. patterns the compiler could not build -------------------------------------------------------------
    const Json& pats = need(m, "patterns", "manifest");
    std::set<uint32_t> failed_ids;
    for (const Json& f : need(pats, "failed_ids", "patterns").items()) failed_ids.insert(static_cast<uint32_t>(f.as_int()));
    for (uint32_t id : failed_ids) {
        if (!data->pattern_index_by_id.count(id)) bad("manifest lists failed pattern " + std::to_string(id) + " that is not in the snapshot");
        info.failed_pattern_ids.push_back(id);
    }
    info.patterns_failed = static_cast<int>(failed_ids.size());

    Pcre2Limits pl = cfg.pcre2;
    std::vector<int> prefilter_indices;
    if (backend_name == "hyperscan") {
#ifdef APG_WITH_HYPERSCAN
        if (hs_valid_platform() != HS_SUCCESS) {
            throw Error(Status::Platform, "this CPU does not provide the instruction set required by Hyperscan (SSSE3)");
        }
        if (info.hs_version != HsBackend::library_version()) {
            throw Error(Status::Version, "rule set was compiled with Hyperscan '" + info.hs_version +
                                             "' but this engine is linked with '" + HsBackend::library_version() + "'");
        }
        // CPU features: the database may use the features of the machine it was compiled on.
        hs_platform_info_t host;
        if (hs_populate_platform(&host) != HS_SUCCESS) throw Error(Status::Platform, "hs_populate_platform failed");
        const Json* cf = tgt.get("cpu_features");
        if (cf != nullptr && cf->is_string()) {
            const unsigned long long want = std::stoull(cf->as_string(), nullptr, 16);
            const unsigned long long have = static_cast<unsigned long long>(host.cpu_features);
            if ((want & ~have) != 0ull) {
                throw Error(Status::Platform, "rule set needs CPU features 0x" + cf->as_string() + " that this machine lacks "
                                                  "(compile with --cpu-target generic for a portable database)");
            }
        }
        // A profile may be split into several database shards (one manifest entry each); every pattern is in exactly one.
        std::vector<std::vector<hs_database_t*>> dbs(data->profiles.size());
        auto free_all = [&dbs]() {
            for (std::vector<hs_database_t*>& shards : dbs) {
                for (hs_database_t* db : shards) {
                    if (db != nullptr) hs_free_database(db);
                }
                shards.clear();
            }
        };
        std::vector<int> pattern_in_db(data->patterns.size(), 0);
        try {
            for (const Json& dj : need(files, "databases", "files").items()) {
                const std::string prof = need(dj, "profile", "database").as_string();
                const int pi = data->profile_index(prof);
                if (pi < 0) bad("database for unknown profile '" + prof + "'");
                const std::string db_path = resolve_inside(base_dir, need(dj, "path", "database").as_string());
                const std::string bytes = read_checked(db_path, 1024u << 20);
                if (sha256_hex(bytes) != need(dj, "sha256", "database").as_string()) {
                    bad("database file " + need(dj, "path", "database").as_string() + " does not match its sha256 in the manifest");
                }
                for (const Json& idj : need(dj, "native_ids", "database").items()) {
                    auto it = data->pattern_index_by_id.find(static_cast<uint32_t>(idj.as_int()));
                    if (it == data->pattern_index_by_id.end() || data->patterns[static_cast<size_t>(it->second)].profile != pi) {
                        bad("database '" + prof + "' lists an unknown / foreign pattern id");
                    }
                    if (pattern_in_db[static_cast<size_t>(it->second)] != 0) {
                        bad("pattern " + std::to_string(idj.as_int()) + " is listed by more than one database");
                    }
                    pattern_in_db[static_cast<size_t>(it->second)] = 1;
                    data->patterns[static_cast<size_t>(it->second)].cls = PatternClass::Native;
                }
                for (const Json& idj : need(dj, "prefilter_ids", "database").items()) {
                    auto it = data->pattern_index_by_id.find(static_cast<uint32_t>(idj.as_int()));
                    if (it == data->pattern_index_by_id.end() || data->patterns[static_cast<size_t>(it->second)].profile != pi) {
                        bad("database '" + prof + "' lists an unknown / foreign pattern id");
                    }
                    if (pattern_in_db[static_cast<size_t>(it->second)] != 0) {
                        bad("pattern " + std::to_string(idj.as_int()) + " is listed by more than one database");
                    }
                    pattern_in_db[static_cast<size_t>(it->second)] = 2;
                    data->patterns[static_cast<size_t>(it->second)].cls = PatternClass::Prefilter;
                }
                dbs[static_cast<size_t>(pi)].push_back(HsBackend::deserialize(bytes));
            }
        } catch (...) {
            free_all();
            throw;
        }
        // every pattern must be accounted for: in a database or in the failed list, never both
        for (size_t i = 0; i < data->patterns.size(); ++i) {
            const bool failed = failed_ids.count(data->patterns[i].id) != 0;
            if (failed == (pattern_in_db[i] != 0)) {
                free_all();
                bad("pattern " + std::to_string(data->patterns[i].id) + " is " + (failed ? "both failed and compiled" :
                                                                                        "neither compiled nor listed as failed"));
            }
            if (pattern_in_db[i] == 2) prefilter_indices.push_back(static_cast<int>(i));
            if (pattern_in_db[i] == 1) ++info.patterns_native;
            if (pattern_in_db[i] == 2) ++info.patterns_prefilter;
        }
        rs->backend.reset(new HsBackend(*rs->data, std::move(dbs)));
#else
        throw Error(Status::Platform, "this build of the engine has no Hyperscan support (rule set backend is 'hyperscan'); "
                                      "build with -DAPG_WITH_HYPERSCAN=ON or compile the rules with --backend pcre2_fallback");
#endif
    } else if (backend_name == "pcre2_fallback") {
        std::unique_ptr<Pcre2Backend> pb(new Pcre2Backend(*rs->data, pl));
        const auto& fails = pb->set().failures();
        std::set<uint32_t> failed_now;
        for (const auto& f : fails) failed_now.insert(data->patterns[static_cast<size_t>(f.first)].id);
        if (failed_now != failed_ids) {
            throw Error(Status::Version, "PCRE2 " + info.pcre2_version + " compiles a different set of patterns than the one the "
                                         "rule set was built with (" + std::to_string(failed_now.size()) + " vs " +
                                         std::to_string(failed_ids.size()) + " failures); recompile the rules on this machine");
        }
        info.patterns_native = static_cast<int>(data->patterns.size()) - info.patterns_failed;
        rs->backend = std::move(pb);
    } else {
        throw Error(Status::Config, "unknown backend '" + backend_name + "' in manifest");
    }

    // ---- 4. PCRE2 verifier for Hyperscan prefilter candidates ------------------------------------------------------
    if (!prefilter_indices.empty()) {
        rs->verifier.reset(new Pcre2Set(*rs->data, prefilter_indices, pl));
        if (!rs->verifier->failures().empty()) {
            throw Error(Status::Version, "PCRE2 " + info.pcre2_version + " cannot compile prefilter pattern: " +
                                             rs->verifier->failures().front().second +
                                             "; recompile the rules on this machine");
        }
    }
    // ---- 4b. span locator for the evidence text: PCRE2 (interpreter, no JIT) over every pattern that can match ----------------
    {
        std::vector<int> all;
        for (size_t i = 0; i < rs->data->patterns.size(); ++i) {
            if (i < rs->disabled_pattern.size() && rs->disabled_pattern[i]) continue;
            all.push_back(static_cast<int>(i));
        }
        Pcre2Limits ll = pl;
        ll.use_jit = false;
        rs->locator.reset(new Pcre2Set(*rs->data, all, ll));   // a pattern PCRE2 rejects only loses its evidence text
    }
    // ---- 5. prove that a scratch space can be created (reload must fail HERE, not on the first scan) ------------------
    {
        LoadedRuleset::Lease lease = rs->lease();
        (void)lease.get();
    }
    return std::shared_ptr<LoadedRuleset>(std::move(rs));
}

}  // namespace apg
