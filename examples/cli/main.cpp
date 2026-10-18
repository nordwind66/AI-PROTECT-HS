// ai-prompt-guard -- command line front end.
//
//   compile   published SQLite snapshot -> Hyperscan databases + manifest (build time, needs Hyperscan)
//   verify    load a compiled rule set and verify hashes / platform / versions
//   scan      scan text through the PUBLIC C ABI (the same code path as the shared library)
//   bench     explicit benchmark (never started automatically)
//   versions  list rule-set versions of a rule database (read-only)
//   db / rules / import / ...  are implemented by tools/rules.py and forwarded to it (needs Python 3)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <io.h>
#  include <fcntl.h>
#else
#  include <sys/wait.h>
#endif

#include "../include/ai_prompt_guard.h"
#include "../engine/core/fileio.h"
#include "../engine/core/json.h"
#include "../engine/core/platform.h"
#include "../engine/ruleset/compiler.h"
#include "../engine/storage/sqlite_store.h"
#include "cli_util.h"

namespace apgcli {

std::string read_stdin() {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
#endif
    std::string data;
    char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), stdin)) > 0) data.append(buf, n);
    return data;
}

void write_stdout(const std::string& s) {
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    std::fwrite(s.data(), 1, s.size(), stdout);
    std::fflush(stdout);
}

void write_stderr(const std::string& s) {
    std::fwrite(s.data(), 1, s.size(), stderr);
    std::fflush(stderr);
}

}  // namespace apgcli

namespace {

using apgcli::Args;

const char* kUsage =
    "ai-prompt-guard " APG_ENGINE_VERSION " (ABI " "1.0" ")\n"
    "\n"
    "Usage: ai-prompt-guard <command> [options]\n"
    "\n"
    "Engine commands (native):\n"
    "  compile   --db FILE --version V [--out DIR] [--target native] [--backend hyperscan|pcre2_fallback]\n"
    "            [--cpu-target generic|host] [--force] [--strict]\n"
    "            [--jobs N] [--shards N] [--pattern-timeout SEC] [--shard-timeout SEC] [--relax-repeat N]\n"
    "            --jobs           worker threads (default: one per CPU thread, at most 16; 1 = strictly sequential)\n"
    "            --shards         Hyperscan databases per profile (default: automatic, about one per worker)\n"
    "            --pattern-timeout  give up on one compile attempt of one pattern after SEC seconds (default 30)\n"
    "            --shard-timeout  give up on one database after SEC seconds and split it (default 1800)\n"
    "            --relax-repeat   counted repeats above N become {n,} in the prefilter form (a superset: PCRE2 confirms every\n"
    "                             candidate). Used as the last resort, and straight away for patterns with a repeat above 2N,\n"
    "                             which Hyperscan cannot build natively in UTF-8 mode (default 32; 0 = off)\n"
    "  verify    --manifest FILE\n"
    "  info      --manifest FILE\n"
    "  scan      --manifest FILE (--text STR | --file FILE | --json-file FILE | --stdin) [--source S]\n"
    "            [--context key=value]... [--config FILE] [--request-id ID] [--pretty] [--exit-on-detect]\n"
    "  scan-batch --manifest FILE --requests FILE.jsonl [--out FILE.jsonl] [--config FILE]\n"
    "            one request document (schemas/request.schema.json) per line -> one result line per request;\n"
    "            the rule set is loaded once (used by the differential tests and by tests/e2e)\n"
    "  bench     --manifest FILE --dataset DIR [--sizes 256,1024,...] [--iterations N] [--threads T]\n"
    "            [--out FILE]         (explicit benchmark; never run automatically)\n"
    "  versions  --db FILE\n"
    "\n"
    "Rule-management commands (forwarded to python tools/rules.py; needs Python 3):\n"
    "  db init|check|backup|snapshot|restore, sources sync|verify, import, diff, validate, stage, publish,\n"
    "  rollback, activate, rules list|show|enable|disable|add|update|versions|diff|validate|publish|rollback|import\n"
    "  e.g.  ai-prompt-guard rules publish --db data/ai_prompt_rules.db --version 1.0.0\n"
    "\n"
    "Set APG_PYTHON to choose the interpreter and APG_RULES_PY to point at tools/rules.py.\n";

int fail(const std::string& msg, int code = 1) {
    apgcli::write_stderr("error: " + msg + "\n");
    return code;
}

std::string status_text(apg_status_t st) {
    std::string s = apg_status_string(st);
    const char* e = apg_last_error();
    if (e != nullptr && e[0] != '\0') s += ": " + std::string(e);
    return s;
}

// ---- config -----------------------------------------------------------------------------------------------
std::string make_config(const std::string& manifest, const Args& args) {
    const std::string cfg_file = args.get("--config");
    if (cfg_file.empty()) {
        std::string out;
        apg::JsonWriter w(out);
        w.begin_object();
        w.kv_string("manifest_path", manifest);
        w.end_object();
        return out;
    }
    std::string text, err;
    if (!apg::read_file(cfg_file, &text, &err, 1u << 20)) throw apg::Error(apg::Status::Config, err);
    apg::Json doc = apg::Json::parse(text, 16);
    apg::Json merged = apg::Json::make_object();
    bool had_manifest = false;
    for (const auto& kv : doc.members()) {
        if (kv.first == "manifest_path") {
            had_manifest = true;
            merged.set("manifest_path", apg::Json::make_string(manifest));
        } else {
            merged.set(kv.first, kv.second);
        }
    }
    if (!had_manifest) merged.set("manifest_path", apg::Json::make_string(manifest));
    return apg::json_dump_canonical(merged);
}

struct Ctx {
    apg_context_t* ctx = nullptr;
    ~Ctx() {
        if (ctx != nullptr) apg_destroy(ctx);
    }
};

int open_context(const Args& args, Ctx* holder) {
    const std::string manifest = args.get("--manifest");
    if (manifest.empty()) return fail("--manifest is required");
    std::string cfg;
    try {
        cfg = make_config(manifest, args);
    } catch (const std::exception& e) {
        return fail(e.what());
    }
    const apg_status_t st = apg_create(reinterpret_cast<const uint8_t*>(cfg.data()), cfg.size(), &holder->ctx);
    if (st != APG_OK) return fail(status_text(st), 2);
    return 0;
}

std::string maybe_pretty(const std::string& json, bool pretty) {
    if (!pretty) return json + "\n";
    try {
        return apg::json_dump_pretty(apg::Json::parse(json));
    } catch (...) {
        return json + "\n";
    }
}

// ---- commands ---------------------------------------------------------------------------------------------
// Reads an integer option; throws apg::Error(Config) when it is present but not a number in [lo, hi].
long long int_option(const Args& args, const std::string& name, long long def, long long lo, long long hi) {
    if (!args.has_value(name)) return def;
    const std::string text = args.get(name);
    char* end = nullptr;
    const long long v = std::strtoll(text.c_str(), &end, 10);
    if (text.empty() || end == nullptr || *end != '\0' || v < lo || v > hi) {
        throw apg::Error(apg::Status::Config, name + " expects an integer between " + std::to_string(lo) + " and " +
                                                  std::to_string(hi) + ", got '" + text + "'");
    }
    return v;
}

int cmd_compile_impl(const Args& args) {
    apg::CompileOptions opt;
    opt.db_path = args.get("--db");
    opt.version = args.get("--version");
    opt.out_dir = args.get("--out", "dist");
    opt.backend = args.get("--backend", "hyperscan");
    opt.cpu_target = args.get("--cpu-target", "generic");
    opt.force = args.flag("--force");
    opt.strict = args.flag("--strict");
    const std::string target = args.get("--target", "native");
    if (opt.db_path.empty() || opt.version.empty()) return fail("--db and --version are required");
    if (target != "native") {
        return fail("only --target native is supported: Hyperscan databases are valid only for the Hyperscan version and CPU "
                    "features of the machine they were built for, so compile on the target machine");
    }
    try {
        opt.jobs = static_cast<int>(int_option(args, "--jobs", opt.jobs, 1, 256));
        opt.shards = static_cast<int>(int_option(args, "--shards", opt.shards, 1, 256));
        opt.pattern_timeout_s = static_cast<int>(int_option(args, "--pattern-timeout", opt.pattern_timeout_s, 1, 86400));
        opt.shard_timeout_s = static_cast<int>(int_option(args, "--shard-timeout", opt.shard_timeout_s, 1, 86400));
        opt.relax_repeat = static_cast<unsigned>(int_option(args, "--relax-repeat", static_cast<long long>(opt.relax_repeat), 0, 100000));
        const apg::CompileReport r = apg::compile_ruleset(opt, [](const std::string& line) {
            apgcli::write_stderr("[compile] " + line + "\n");
        });
        std::string out;
        apg::JsonWriter w(out);
        w.begin_object();
        w.kv_string("manifest", r.manifest_path);
        w.kv_int("patterns", r.total);
        w.kv_int("native", r.native);
        w.kv_int("prefilter", r.prefilter);
        w.kv_int("downgraded_to_prefilter", r.downgraded);
        w.kv_int("relaxed_repeats", r.relaxed);
        w.kv_int("failed", r.failed);
        w.kv_int("databases", r.databases);
        w.kv_int("jobs", r.jobs);
        w.kv_double("elapsed_s", r.elapsed_s, 1);
        w.kv_string("status", r.failed == 0 ? "ok" : "partial");
        w.end_object();
        apgcli::write_stdout(maybe_pretty(out, true));
        if (r.failed != 0) {
            apgcli::write_stderr("warning: " + std::to_string(r.failed) + " pattern(s) were isolated; see build_report.json\n");
        }
        return 0;
    } catch (const apg::Error& e) {
        return fail(std::string(apg::status_name(e.status())) + ": " + e.what(), 2);
    }
}

int cmd_compile(const Args& args) {
    const int rc = cmd_compile_impl(args);
    if (apg::compile_abandoned_workers() > 0) {
        // A Hyperscan call did not return within its deadline and its thread cannot be stopped: leave without running
        // static destructors while that thread may still use library state.
        apgcli::write_stderr("note: " + std::to_string(apg::compile_abandoned_workers()) +
                             " compiler thread(s) were abandoned at their time limit; exiting without waiting for them\n");
        std::fflush(nullptr);
        std::_Exit(rc);
    }
    return rc;
}

int cmd_verify_or_info(const Args& args, bool info_only) {
    Ctx c;
    if (const int rc = open_context(args, &c)) return rc;
    uint8_t* json = nullptr;
    size_t len = 0;
    const apg_status_t st = apg_get_info(c.ctx, &json, &len);
    if (st != APG_OK) return fail(status_text(st), 2);
    const std::string text(reinterpret_cast<char*>(json), len);
    apg_free_buffer(json);
    apgcli::write_stdout(maybe_pretty(text, true));
    if (!info_only) apgcli::write_stderr("OK: manifest, hashes, platform, Hyperscan/PCRE2 versions and databases verified\n");
    return 0;
}

// Builds the structured request (schemas/request.schema.json) used when --context / --request-id are given:
// the plain apg_scan_text() entry point has no place for them.
std::string build_request(const std::string& text, const std::string& source, const std::vector<std::string>& contexts,
                          const std::string& request_id) {
    std::string out;
    apg::JsonWriter w(out);
    w.begin_object();
    w.kv_int("schema_version", 1);
    if (!request_id.empty()) w.kv_string("request_id", request_id);
    w.kv_string("source", source);
    w.kv_string("text", text);
    if (!contexts.empty()) {
        w.key("context");
        w.begin_object();
        for (const std::string& kv : contexts) {
            const size_t eq = kv.find('=');
            if (eq == std::string::npos || eq == 0) throw apg::Error(apg::Status::InvalidArgument, "--context expects key=value, got '" + kv + "'");
            w.kv_string(kv.substr(0, eq), kv.substr(eq + 1));
        }
        w.end_object();
    }
    w.end_object();
    return out;
}

int cmd_scan(const Args& args) {
    Ctx c;
    if (const int rc = open_context(args, &c)) return rc;
    uint8_t* json = nullptr;
    size_t len = 0;
    apg_status_t st;
    const std::string source = args.get("--source", "user_input");
    const std::vector<std::string> contexts = args.get_all("--context");
    const std::string request_id = args.get("--request-id");
    const bool structured = !contexts.empty() || !request_id.empty();
    auto scan_plain_text = [&](const std::string& text) -> apg_status_t {
        if (!structured) {
            return apg_scan_text(c.ctx, reinterpret_cast<const uint8_t*>(text.data()), text.size(), source.c_str(), &json, &len);
        }
        const std::string req = build_request(text, source, contexts, request_id);
        return apg_scan_json(c.ctx, reinterpret_cast<const uint8_t*>(req.data()), req.size(), &json, &len);
    };
    if (args.has_value("--text")) {
        st = scan_plain_text(args.get("--text"));
    } else if (args.has_value("--file") || args.flag("--stdin")) {
        std::string text, err;
        if (args.flag("--stdin")) {
            text = apgcli::read_stdin();
        } else if (!apg::read_file(args.get("--file"), &text, &err)) {
            return fail(err);
        }
        st = scan_plain_text(text);
    } else if (args.has_value("--json-file")) {
        std::string req, err;
        if (!apg::read_file(args.get("--json-file"), &req, &err)) return fail(err);
        st = apg_scan_json(c.ctx, reinterpret_cast<const uint8_t*>(req.data()), req.size(), &json, &len);
    } else {
        return fail("one of --text, --file, --stdin or --json-file is required");
    }
    if (st != APG_OK) return fail(status_text(st), 2);
    const std::string result(reinterpret_cast<char*>(json), len);
    apg_free_buffer(json);
    apgcli::write_stdout(maybe_pretty(result, args.flag("--pretty")));
    if (args.flag("--exit-on-detect")) {
        try {
            const std::string d = apg::Json::parse(result).get("decision")->as_string();
            if (d == "alert") return 10;
            if (d == "review") return 11;
            if (d == "block") return 12;
        } catch (...) {
        }
    }
    return 0;
}

// One request per line in, one result line out (same order). A request that the C ABI refuses (malformed JSON,
// unknown key, oversize) produces {"status":"call_error",...} so that the output always has one line per request.
int cmd_scan_batch(const Args& args) {
    const std::string req_file = args.get("--requests");
    if (req_file.empty()) return fail("--requests is required");
    Ctx c;
    if (const int rc = open_context(args, &c)) return rc;
    std::string data, err;
    if (!apg::read_file(req_file, &data, &err, static_cast<size_t>(1) << 30)) return fail(err);
    std::string out;
    size_t pos = 0, requests = 0, call_errors = 0;
    while (pos < data.size()) {
        size_t nl = data.find('\n', pos);
        if (nl == std::string::npos) nl = data.size();
        size_t end = nl;
        if (end > pos && data[end - 1] == '\r') --end;
        const std::string line = data.substr(pos, end - pos);
        pos = nl + 1;
        if (line.find_first_not_of(" \t") == std::string::npos) continue;
        uint8_t* json = nullptr;
        size_t len = 0;
        const apg_status_t st = apg_scan_json(c.ctx, reinterpret_cast<const uint8_t*>(line.data()), line.size(), &json, &len);
        if (st == APG_OK) {
            out.append(reinterpret_cast<const char*>(json), len);
            apg_free_buffer(json);
        } else {
            ++call_errors;
            apg::JsonWriter w(out);
            w.begin_object();
            w.kv_string("status", "call_error");
            w.kv_string("apg_status", apg_status_string(st));
            w.kv_string("error", apg_last_error());
            w.end_object();
        }
        out.push_back('\n');
        ++requests;
    }
    const std::string out_file = args.get("--out");
    if (out_file.empty()) {
        apgcli::write_stdout(out);
    } else if (!apg::write_file_atomic(out_file, out, &err)) {
        return fail(err);
    }
    apgcli::write_stderr("[scan-batch] " + std::to_string(requests) + " request(s), " + std::to_string(call_errors) +
                         " refused by the C ABI\n");
    return 0;
}

int cmd_versions(const Args& args) {
    const std::string db = args.get("--db");
    if (db.empty()) return fail("--db is required");
    try {
        apg::SqliteStore store(db);
        for (const auto& v : store.list_versions()) {
            std::printf("%-12s %-10s rules=%-5d patterns=%-6d digest=%.12s published=%s artifacts=%d%s\n", v.version.c_str(),
                        v.status.c_str(), v.rule_count, v.pattern_count, v.content_digest.c_str(), v.published_at.c_str(),
                        v.artifacts, v.active ? "  [ACTIVE]" : "");
        }
        return 0;
    } catch (const apg::Error& e) {
        return fail(e.what(), 2);
    }
}

// ---- forwarding to tools/rules.py ---------------------------------------------------------------------------
std::string shell_quote(const std::string& a) {
#ifdef _WIN32
    std::string q = "\"";
    for (char c : a) {
        if (c == '"') q += "\\\"";
        else q += c;
    }
    q += "\"";
    return q;
#else
    std::string q = "'";
    for (char c : a) {
        if (c == '\'') q += "'\\''";
        else q += c;
    }
    q += "'";
    return q;
#endif
}

std::string find_rules_py(const char* argv0) {
    if (const char* env = std::getenv("APG_RULES_PY")) return env;
    std::vector<std::string> starts;
    starts.push_back(apg::current_dir_utf8());
    if (argv0 != nullptr) starts.push_back(apg::path_dir(argv0));
    for (std::string dir : starts) {
        for (int up = 0; up < 8 && !dir.empty(); ++up) {
            const std::string cand = apg::path_join(apg::path_join(dir, "tools"), "rules.py");
            if (apg::path_exists(cand)) return cand;
            const std::string parent = apg::path_dir(dir);
            if (parent == dir) break;
            dir = parent;
        }
    }
    return std::string();
}

int forward_to_python(const std::vector<std::string>& args, const char* argv0) {
    const std::string rules_py = find_rules_py(argv0);
    if (rules_py.empty()) {
        return fail("cannot find tools/rules.py (run from the project directory or set APG_RULES_PY); rule management is "
                    "implemented in Python", 3);
    }
    std::vector<std::string> interpreters;
    if (const char* env = std::getenv("APG_PYTHON")) interpreters.push_back(env);
#ifdef _WIN32
    interpreters.push_back("py -3");
    interpreters.push_back("python");
#else
    interpreters.push_back("python3");
    interpreters.push_back("python");
#endif
    std::vector<std::string> mapped = args;
    // `ai-prompt-guard rules <cmd> ...` is spelled `rules.py <cmd> ...`
    if (!mapped.empty() && mapped[0] == "rules") mapped.erase(mapped.begin());
    for (const std::string& py : interpreters) {
        std::string cmd = py + " " + shell_quote(rules_py);
        for (const std::string& a : mapped) cmd += " " + shell_quote(a);
#ifdef _WIN32
        cmd = "\"" + cmd + "\"";
#endif
        const int raw = std::system(cmd.c_str());
        if (raw == -1) continue;
#ifdef _WIN32
        if (raw != 9009) return raw;                          // 9009: cmd.exe could not find the interpreter
#else
        const int code = WIFEXITED(raw) ? WEXITSTATUS(raw) : 1;
        if (code != 127) return code;                         // 127: sh could not find the interpreter
#endif
    }
    return fail("no Python 3 interpreter found (tried APG_PYTHON, python3/python)", 3);
}

int dispatch(const std::vector<std::string>& argv_utf8, const char* argv0) {
    if (argv_utf8.empty() || argv_utf8[0] == "help" || argv_utf8[0] == "--help" || argv_utf8[0] == "-h") {
        apgcli::write_stdout(kUsage);
        return argv_utf8.empty() ? 1 : 0;
    }
    if (argv_utf8[0] == "--version" || argv_utf8[0] == "version") {
        apgcli::write_stdout(std::string("ai-prompt-guard ") + APG_ENGINE_VERSION + " abi " + std::to_string(apg_abi_version() >> 16) + "." +
                             std::to_string((apg_abi_version() >> 8) & 0xFF) + "\n");
        return 0;
    }
    const std::string cmd = argv_utf8[0];
    std::vector<std::string> rest(argv_utf8.begin() + 1, argv_utf8.end());
    const Args args(rest);
    if (cmd == "compile") return cmd_compile(args);
    if (cmd == "verify") return cmd_verify_or_info(args, false);
    if (cmd == "info") return cmd_verify_or_info(args, true);
    if (cmd == "scan") return cmd_scan(args);
    if (cmd == "scan-batch") return cmd_scan_batch(args);
    if (cmd == "bench") return apgcli::run_bench(args);
    if (cmd == "versions") return cmd_versions(args);
    static const char* forwarded[] = {"db", "rules", "sources", "import", "diff", "validate", "stage", "publish", "rollback",
                                      "activate", "list", "show", "enable", "disable", "add", "update", "delete",
                                      "inventory", "report", "verify-tests", "register-artifact", "export-snapshot",
                                      "restore-upstream", "eval", "explain"};
    for (const char* f : forwarded) {
        if (cmd == f) return forward_to_python(argv_utf8, argv0);
    }
    apgcli::write_stderr("unknown command '" + cmd + "'\n\n" + kUsage);
    return 1;
}

}  // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        const int n = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s(n > 1 ? static_cast<size_t>(n - 1) : 0, '\0');
        if (n > 1) WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, &s[0], n, nullptr, nullptr);
        args.push_back(s);
    }
    std::string exe;
    if (argc > 0) {
        const int n = WideCharToMultiByte(CP_UTF8, 0, argv[0], -1, nullptr, 0, nullptr, nullptr);
        exe.assign(n > 1 ? static_cast<size_t>(n - 1) : 0, '\0');
        if (n > 1) WideCharToMultiByte(CP_UTF8, 0, argv[0], -1, &exe[0], n, nullptr, nullptr);
    }
    try {
        return dispatch(args, exe.c_str());
    } catch (const std::exception& e) {
        apgcli::write_stderr(std::string("fatal: ") + e.what() + "\n");
        return 70;
    }
}
#else
int main(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.push_back(argv[i]);
    try {
        return dispatch(args, argc > 0 ? argv[0] : nullptr);
    } catch (const std::exception& e) {
        apgcli::write_stderr(std::string("fatal: ") + e.what() + "\n");
        return 70;
    }
}
#endif
