// `ai-prompt-guard bench` -- explicit micro-benchmark of the public C ABI.
//
// It is NEVER started by the build, by the installer or by the test scripts; scripts/bench.sh runs it
// only when a person asks for it. Numbers produced here are measured on the machine that runs the command and
// are not stored anywhere in this repository.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <thread>
#include <vector>

#include "../include/ai_prompt_guard.h"
#include "../src/core/fileio.h"
#include "../src/core/json.h"
#include "cli_util.h"

namespace apgcli {

namespace {

using Clock = std::chrono::steady_clock;

struct Corpus {
    std::vector<std::string> normal;
    std::vector<std::string> attack;
};

std::vector<size_t> parse_sizes(const std::string& s) {
    std::vector<size_t> out;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t comma = s.find(',', pos);
        if (comma == std::string::npos) comma = s.size();
        const std::string tok = s.substr(pos, comma - pos);
        if (!tok.empty()) out.push_back(static_cast<size_t>(std::strtoull(tok.c_str(), nullptr, 10)));
        pos = comma + 1;
    }
    return out;
}

bool load_corpus(const std::string& dir, Corpus* c, std::string* err) {
    std::vector<std::string> names;
    if (!apg::list_directory(dir, &names, err)) return false;
    std::sort(names.begin(), names.end());
    for (const std::string& n : names) {
        const std::string path = apg::path_join(dir, n);
        const bool jsonl = n.size() > 6 && n.compare(n.size() - 6, 6, ".jsonl") == 0;
        const bool txt = n.size() > 4 && n.compare(n.size() - 4, 4, ".txt") == 0;
        if (!jsonl && !txt) continue;
        std::string data, e2;
        if (!apg::read_file(path, &data, &e2, 256u << 20)) {
            *err = e2;
            return false;
        }
        if (txt) {
            c->normal.push_back(data);
            continue;
        }
        size_t pos = 0;
        while (pos < data.size()) {
            size_t nl = data.find('\n', pos);
            if (nl == std::string::npos) nl = data.size();
            const std::string line = data.substr(pos, nl - pos);
            pos = nl + 1;
            if (line.find_first_not_of(" \t\r") == std::string::npos) continue;
            try {
                const apg::Json j = apg::Json::parse(line, 16);
                const apg::Json* t = j.get("text");
                if (t == nullptr || !t->is_string()) continue;
                std::string label;
                if (const apg::Json* l = j.get("label")) {
                    if (l->is_string()) label = l->as_string();
                }
                if (label == "injection" || label == "attack" || label == "malicious") c->attack.push_back(t->as_string());
                else c->normal.push_back(t->as_string());
            } catch (const apg::Error&) {
                // skip malformed lines
            }
        }
    }
    return true;
}

std::string build_sample(const std::vector<std::string>& pool, size_t target, size_t seed) {
    std::string s;
    if (pool.empty()) return s;
    size_t i = seed;
    while (s.size() < target) {
        s += pool[i % pool.size()];
        s += ' ';
        ++i;
    }
    if (s.size() > target) {
        size_t cut = target;
        while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0u) == 0x80u) --cut;   // never split a UTF-8 sequence
        s.resize(cut);
    }
    return s;
}

double percentile(std::vector<double>& v, double p) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const size_t idx = static_cast<size_t>(p * static_cast<double>(v.size() - 1) + 0.5);
    return v[std::min(idx, v.size() - 1)];
}

long rss_kb() {
#ifdef __linux__
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.compare(0, 6, "VmRSS:") == 0) return std::strtol(line.c_str() + 6, nullptr, 10);
    }
#endif
    return -1;
}

}  // namespace

int run_bench(const Args& args) {
    const std::string manifest = args.get("--manifest");
    const std::string dataset = args.get("--dataset");
    if (manifest.empty() || dataset.empty()) {
        write_stderr("error: bench needs --manifest and --dataset\n");
        return 1;
    }
    std::vector<size_t> sizes = parse_sizes(args.get("--sizes", "256,1024,4096,16384,65536"));
    const size_t iterations = static_cast<size_t>(std::strtoull(args.get("--iterations", "1000").c_str(), nullptr, 10));
    std::vector<size_t> thread_counts = parse_sizes(args.get("--threads", "1"));
    if (thread_counts.empty()) thread_counts.push_back(1);
    Corpus corpus;
    std::string err;
    if (!load_corpus(dataset, &corpus, &err)) {
        write_stderr("error: " + err + "\n");
        return 1;
    }
    if (corpus.normal.empty() && corpus.attack.empty()) {
        write_stderr("error: no .jsonl/.txt samples found in " + dataset + "\n");
        return 1;
    }
    if (corpus.normal.empty()) corpus.normal.push_back("The quarterly report shows steady growth in all regions this year.");
    if (corpus.attack.empty()) corpus.attack = corpus.normal;
    const std::vector<std::string> filler = {"The weather was mild and the train arrived on time.",
                                              "Please send the quarterly figures to the finance team by Friday.",
                                              "Our library opens at nine and closes at six on weekdays."};

    std::string cfg_text = "{\"manifest_path\":" + apg::json_quote(manifest) + "}";
    const long rss_before = rss_kb();
    const auto t0 = Clock::now();
    apg_context_t* ctx = nullptr;
    apg_status_t st = apg_create(reinterpret_cast<const uint8_t*>(cfg_text.data()), cfg_text.size(), &ctx);
    const double load_ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
    if (st != APG_OK) {
        write_stderr(std::string("error: ") + apg_status_string(st) + ": " + apg_last_error() + "\n");
        return 2;
    }
    const long rss_after = rss_kb();

    std::string out;
    apg::JsonWriter w(out);
    w.begin_object();
    w.kv_string("engine_version", apg_engine_version());
    w.kv_uint("hardware_concurrency", std::thread::hardware_concurrency());
    w.kv_double("load_ms", load_ms, 3);
    w.kv_int("rss_kb_before_load", rss_before);
    w.kv_int("rss_kb_after_load", rss_after);
    w.kv_uint("iterations_per_case", iterations);
    w.key("results");
    w.begin_array();
    struct Mix {
        const char* name;
        const std::vector<std::string>* pool;
    };
    const Mix mixes[] = {{"nohit_filler", &filler}, {"lowhit_normal_text", &corpus.normal}, {"highhit_attack_text", &corpus.attack}};
    for (size_t size : sizes) {
        for (const Mix& mix : mixes) {
            std::vector<std::string> samples;
            for (size_t k = 0; k < 64; ++k) samples.push_back(build_sample(*mix.pool, size, k * 7));
            // one untimed pass: how many samples actually trigger something (honest hit rate)
            size_t flagged = 0, total_matches = 0;
            for (const std::string& s : samples) {
                uint8_t* res = nullptr;
                size_t rl = 0;
                if (apg_scan_text(ctx, reinterpret_cast<const uint8_t*>(s.data()), s.size(), "user_input", &res, &rl) == APG_OK) {
                    try {
                        const apg::Json j = apg::Json::parse(reinterpret_cast<const char*>(res), rl, 16);
                        const size_t n = j.get("matched_rules")->items().size();
                        if (n > 0) ++flagged;
                        total_matches += n;
                    } catch (const apg::Error&) {
                    }
                    apg_free_buffer(res);
                }
            }
            for (size_t tc : thread_counts) {
                const size_t threads = std::max<size_t>(tc, 1);
                const size_t per_thread = std::max<size_t>(iterations / threads, 1);
                std::vector<std::vector<double>> lat(threads);
                std::atomic<int> failures(0);
                const auto start = Clock::now();
                std::vector<std::thread> pool;
                for (size_t t = 0; t < threads; ++t) {
                    pool.emplace_back([&, t] {
                        lat[t].reserve(per_thread);
                        for (size_t i = 0; i < per_thread; ++i) {
                            const std::string& s = samples[(i + t * 13) % samples.size()];
                            uint8_t* res = nullptr;
                            size_t rl = 0;
                            const auto a = Clock::now();
                            const apg_status_t r = apg_scan_text(ctx, reinterpret_cast<const uint8_t*>(s.data()), s.size(), "user_input", &res, &rl);
                            const auto b = Clock::now();
                            if (r != APG_OK) ++failures;
                            apg_free_buffer(res);
                            lat[t].push_back(std::chrono::duration<double, std::micro>(b - a).count());
                        }
                    });
                }
                for (std::thread& th : pool) th.join();
                const double wall_s = std::chrono::duration<double>(Clock::now() - start).count();
                std::vector<double> all;
                for (auto& v : lat) all.insert(all.end(), v.begin(), v.end());
                const double scans = static_cast<double>(all.size());
                w.begin_object();
                w.kv_uint("size_bytes", size);
                w.kv_string("mix", mix.name);
                w.kv_uint("threads", threads);
                w.kv_uint("scans", all.size());
                w.kv_double("samples_flagged_ratio", samples.empty() ? 0.0 : static_cast<double>(flagged) / static_cast<double>(samples.size()), 4);
                w.kv_double("avg_matched_rules", samples.empty() ? 0.0 : static_cast<double>(total_matches) / static_cast<double>(samples.size()), 3);
                w.kv_double("p50_us", percentile(all, 0.50), 2);
                w.kv_double("p95_us", percentile(all, 0.95), 2);
                w.kv_double("p99_us", percentile(all, 0.99), 2);
                w.kv_double("scans_per_second", wall_s > 0 ? scans / wall_s : 0.0, 1);
                w.kv_double("throughput_mb_per_second", wall_s > 0 ? scans * static_cast<double>(size) / wall_s / 1048576.0 : 0.0, 2);
                w.kv_int("failed_scans", failures.load());
                w.end_object();
            }
        }
    }
    w.end_array();
    w.end_object();
    apg_destroy(ctx);
    const std::string pretty = apg::json_dump_pretty(apg::Json::parse(out));
    const std::string out_file = args.get("--out");
    if (!out_file.empty()) {
        std::string e2;
        if (!apg::write_file_atomic(out_file, pretty, &e2)) {
            write_stderr("error: " + e2 + "\n");
            return 1;
        }
    }
    write_stdout(pretty);
    return 0;
}

}  // namespace apgcli
