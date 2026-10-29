#include "scanner.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <cstring>
#include <map>
#include <set>

#include "json.h"
#include "utf8.h"

namespace apg {

namespace {

enum Tri : int8_t { kFalse = 0, kTrue = 1, kUnknown = 2 };

struct HitInfo {
    uint32_t pattern_index;
    int view;                 // ViewKind of the scanned view
    uint64_t end_view;        // end offset inside that view
    uint64_t end_original;    // best-effort end offset in the ORIGINAL text
};

struct Target {
    std::string name;         // named field, or empty for the primary text
    const char* text = nullptr;
    size_t len = 0;
    std::vector<int> fields;  // rule field indexes this target supplies
    Normalized norm[kViewKindCount];
    bool computed[kViewKindCount] = {};
    bool changed[kViewKindCount] = {};
    std::vector<uint64_t> bits;
    std::vector<HitInfo> hits;
    unsigned views_scanned = 0;           // bit mask of the effective views that were scanned (bit = ViewKind)

    bool has_hit(uint32_t pi) const { return (bits[pi >> 6] >> (pi & 63)) & 1ull; }
    const HitInfo* hit_info(uint32_t pi) const {
        for (const HitInfo& h : hits) {
            if (h.pattern_index == pi) return &h;
        }
        return nullptr;
    }
};

// Returns the text of view `k` of the target. If the view equals the raw text, *changed is false and the raw
// buffer is returned (no copy).
bool get_view(Target& t, ViewKind k, bool want_offsets, const char** data, size_t* len) {
    const int ki = static_cast<int>(k);
    if (k == ViewKind::Raw) {
        *data = t.text;
        *len = t.len;
        return false;
    }
    if (!t.computed[ki]) {
        t.changed[ki] = normalize(k, reinterpret_cast<const uint8_t*>(t.text), t.len, want_offsets, t.norm[ki]);
        t.computed[ki] = true;
    }
    if (t.changed[ki]) {
        *data = t.norm[ki].text.data();
        *len = t.norm[ki].text.size();
        return true;
    }
    *data = t.text;
    *len = t.len;
    return false;
}

uint64_t original_end(const Target& t, ViewKind k, bool changed, uint64_t end_view) {
    if (!changed || k == ViewKind::Raw) return end_view;
    const Normalized& n = t.norm[static_cast<int>(k)];
    if (n.offsets.empty() || end_view == 0 || end_view > n.text.size()) return end_view;
    const uint32_t o = n.offsets[static_cast<size_t>(end_view) - 1];
    if (o >= t.len) return t.len;
    uint32_t cp = 0;
    const size_t l = utf8_decode(reinterpret_cast<const uint8_t*>(t.text) + o, t.len - o, &cp);
    return static_cast<uint64_t>(o) + l;
}

// ---- evidence text ---------------------------------------------------------------------------------------
constexpr size_t kMaxEvidenceBytes = 256;     // matched fragment
constexpr size_t kMaxSentenceBytes = 400;     // sentence around it

// Largest cut <= pos that does not split a UTF-8 sequence.
size_t utf8_floor(const char* s, size_t len, size_t pos) {
    if (pos >= len) return len;
    while (pos > 0 && (static_cast<uint8_t>(s[pos]) & 0xC0u) == 0x80u) --pos;
    return pos;
}

// Length (1 or 3) of a sentence delimiter at `i`, 0 if none: newline, . ! ? ;  and the CJK 。！？；
size_t sentence_delim(const char* s, size_t len, size_t i) {
    const uint8_t c = static_cast<uint8_t>(s[i]);
    if (c == '\n' || c == '.' || c == '!' || c == '?' || c == ';') return 1;
    if (i + 2 < len) {
        const uint8_t c1 = static_cast<uint8_t>(s[i + 1]), c2 = static_cast<uint8_t>(s[i + 2]);
        if (c == 0xE3 && c1 == 0x80 && c2 == 0x82) return 3;                                   // 。
        if (c == 0xEF && c1 == 0xBC && (c2 == 0x81 || c2 == 0x9F || c2 == 0x9B)) return 3;     // ！ ？ ；
    }
    return 0;
}

// The sentence of `text` that contains [so, eo): from after the previous delimiter to the next one (included), at most
// kMaxSentenceBytes around the match. *truncated is set when the sentence had to be cut.
std::string sentence_around(const char* text, size_t len, size_t so, size_t eo, bool* truncated) {
    size_t b = so;
    while (b > 0) {
        size_t k = b - 1;
        while (k > 0 && (static_cast<uint8_t>(text[k]) & 0xC0u) == 0x80u) --k;      // start of the previous character
        if (sentence_delim(text, len, k) != 0 && k + sentence_delim(text, len, k) <= b) break;
        b = k;
    }
    size_t e = eo;
    while (e < len) {
        const size_t d = sentence_delim(text, len, e);
        if (d != 0) { e += d; break; }
        ++e;
        while (e < len && (static_cast<uint8_t>(text[e]) & 0xC0u) == 0x80u) ++e;
    }
    while (b < e && (text[b] == ' ' || text[b] == '\t' || text[b] == '\r' || text[b] == '\n')) ++b;
    if (e - b > kMaxSentenceBytes) {
        const size_t room = kMaxSentenceBytes > (eo - so) ? (kMaxSentenceBytes - (eo - so)) / 2 : 0;
        size_t nb = so > room ? so - room : 0;
        size_t ne = std::min(len, eo + room);
        if (nb < b) nb = b;
        if (ne > e) ne = e;
        b = utf8_floor(text, len, nb);
        e = utf8_floor(text, len, ne);
        *truncated = true;
    }
    return std::string(text + b, e - b);
}

int decision_code(const std::string& d) { return d == "allow" ? 0 : d == "review" ? 1 : d == "alert" ? 2 : 3; }

std::string decision_for_error(const Config& cfg) {
    const std::string& s = cfg.policy.on_error;
    if (s == "block" && !cfg.policy.allow_block) return "review";
    return s;
}

struct Matched {
    const RuleDef* rule;
    std::vector<uint32_t> pattern_ids;
    std::vector<std::pair<const Target*, uint32_t>> evidence;   // (target, pattern index)
    std::vector<std::string> evidence_fields;
    double risk;
    bool counted;
};

struct NeedsCtx {
    const RuleDef* rule;
    std::string reason;
    std::vector<std::string> missing;
    std::vector<uint32_t> pattern_ids;
    double risk;
};

// Three-valued truth of a rule's condition tree; leaf(const LeafDef&) returns the state of one leaf.
template <class LeafFn>
int8_t eval_rule(const RuleDef& r, std::vector<int8_t>& vals, LeafFn&& leaf) {
    vals.assign(r.nodes.size(), static_cast<int8_t>(kFalse));
    for (size_t ni = 0; ni < r.nodes.size(); ++ni) {          // children always precede their parent
        const CondNode& n = r.nodes[ni];
        int8_t v = kFalse;
        if (n.op == CondNode::Leaf) {
            v = leaf(r.leaves[static_cast<size_t>(n.leaf)]);
        } else if (n.op == CondNode::Any) {
            bool any_true = false, all_false = true;
            for (int k : n.kids) {
                if (vals[static_cast<size_t>(k)] == kTrue) any_true = true;
                if (vals[static_cast<size_t>(k)] != kFalse) all_false = false;
            }
            v = any_true ? kTrue : (all_false ? kFalse : kUnknown);
        } else if (n.op == CondNode::All) {
            bool any_false = false, all_true = true;
            for (int k : n.kids) {
                if (vals[static_cast<size_t>(k)] == kFalse) any_false = true;
                if (vals[static_cast<size_t>(k)] != kTrue) all_true = false;
            }
            v = any_false ? kFalse : (all_true ? kTrue : kUnknown);
        } else {  // Not
            const int8_t c = vals[static_cast<size_t>(n.kids[0])];
            v = c == kUnknown ? kUnknown : (c == kTrue ? kFalse : kTrue);
        }
        vals[ni] = v;
    }
    return vals[static_cast<size_t>(r.root)];
}

double combine(const std::vector<double>& risks, const std::vector<std::string>& groups) {
    // best risk per score group (rules without group count individually), then noisy-OR
    std::map<std::string, double> best;
    double prod = 1.0;
    for (size_t i = 0; i < risks.size(); ++i) {
        if (groups[i].empty()) {
            prod *= (1.0 - risks[i]);
        } else {
            double& b = best[groups[i]];
            if (risks[i] > b) b = risks[i];
        }
    }
    for (const auto& kv : best) prod *= (1.0 - kv.second);
    return 1.0 - prod;
}

void write_error_result(const LoadedRuleset& rs, const Config& cfg, const ScanInput& in, const char* error_code,
                        const std::string& detail, size_t text_bytes, uint64_t duration_us, std::string& out,
                        ScanVerdict* verdict) {
    if (verdict != nullptr) {
        verdict->decision = decision_code(decision_for_error(cfg));
        verdict->scan_error = true;
        verdict->score = 0.0;
        verdict->matched_rules = 0;
        return;
    }
    JsonWriter w(out);
    w.begin_object();
    w.kv_int("schema_version", 1);
    w.key("request_id");
    if (in.has_request_id) w.value_string(in.request_id); else w.value_null();
    w.kv_string("status", "error");
    w.kv_string("decision", decision_for_error(cfg));
    w.kv_double("score", 0.0);
    w.kv_string("risk_level", "none");
    w.kv_string("ruleset_version", rs.data->version);
    w.kv_string("engine_version", APG_ENGINE_VERSION);
    w.kv_string("backend", rs.backend->name());
    w.key("matched_rules");
    w.begin_array();
    w.end_array();
    w.key("needs_context");
    w.begin_array();
    w.end_array();
    w.key("inputs");
    w.begin_object();
    w.kv_uint("text_bytes", text_bytes);
    w.end_object();
    w.key("warnings");
    w.begin_array();
    w.value_string(detail);
    w.end_array();
    w.kv_uint("duration_us", duration_us);
    w.kv_string("error_code", error_code);
    w.end_object();
}

}  // namespace

// Where a hit matched. The span comes from re-matching the pattern with PCRE2 on the scanned view (Hyperscan only reports
// where a match ENDS).
struct Span {
    uint64_t vs = 0, ve = 0;      // span inside the scanned view
    uint64_t so = 0, eo = 0;      // the same span in the ORIGINAL text
    ViewKind vk = ViewKind::Raw;
    const char* vdata = nullptr;
};

// Finds where a hit matched: re-matches the pattern with PCRE2 on the scanned view and maps the span to the original text.
static bool locate_span(const LoadedRuleset& rs, ThreadScratch& sc, const Target& t, const HitInfo& h, Span* out) {
    if (!rs.locator || !sc.locate || !rs.locator->has(static_cast<int>(h.pattern_index))) return false;
    const ViewKind vk = static_cast<ViewKind>(h.view);
    const char* vdata = t.text;
    size_t vlen = t.len;
    if (vk != ViewKind::Raw) {
        const Normalized& n = t.norm[h.view];
        vdata = n.text.data();
        vlen = n.text.size();
    }
    uint64_t vs = 0, ve = 0;
    int perr = 0;
    if (rs.locator->match(static_cast<int>(h.pattern_index), vdata, vlen, *sc.locate, &ve, &perr, &vs) != Pcre2Set::Result::Match) return false;
    if (ve > vlen || vs > ve) return false;
    uint64_t so = vs, eo = ve;
    if (vk != ViewKind::Raw) {
        const Normalized& n = t.norm[h.view];
        if (n.offsets.size() != n.text.size() + 1) return false;     // offsets were not recorded
        so = n.offsets[static_cast<size_t>(vs)];
        eo = original_end(t, vk, true, ve);
    }
    if (eo > t.len || so >= eo) return false;
    out->vs = vs; out->ve = ve; out->so = so; out->eo = eo; out->vk = vk; out->vdata = vdata;
    return true;
}

// Adds start_original / matched_text / normalized_text / sentence to an evidence object (nothing is added when the span cannot be located).
static void emit_evidence_text(JsonWriter& w, const LoadedRuleset& rs, ThreadScratch& sc, const Target& t, const HitInfo& h) {
    Span sp;
    if (!locate_span(rs, sc, t, h, &sp)) return;
    const ViewKind vk = sp.vk;
    const char* vdata = sp.vdata;
    const uint64_t vs = sp.vs, ve = sp.ve, so = sp.so, eo = sp.eo;
    bool cut = false;
    size_t take = static_cast<size_t>(eo - so);
    if (take > kMaxEvidenceBytes) {
        take = utf8_floor(t.text + so, t.len - so, kMaxEvidenceBytes);
        cut = true;
    }
    w.kv_uint("start_original", so);
    w.kv_string("matched_text", std::string(t.text + so, take));
    if (vk != ViewKind::Raw) {
        std::string viewed(vdata + vs, static_cast<size_t>(ve - vs));
        if (viewed.size() > kMaxEvidenceBytes) {
            viewed.resize(utf8_floor(viewed.data(), viewed.size(), kMaxEvidenceBytes));
            cut = true;
        }
        if (viewed != std::string(t.text + so, take)) w.kv_string("normalized_text", viewed);
    }
    bool sentence_cut = false;
    w.kv_string("sentence", sentence_around(t.text, t.len, static_cast<size_t>(so), static_cast<size_t>(eo), &sentence_cut));
    if (cut || sentence_cut) w.kv_bool("text_truncated", true);
}

std::string run_scan(const LoadedRuleset& rs, const Config& cfg, const ScanInput& in, ThreadScratch& sc,
                     ScanVerdict* verdict) {
    const auto t_start = std::chrono::steady_clock::now();
    auto elapsed_us = [&]() -> uint64_t {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                         std::chrono::steady_clock::now() - t_start).count());
    };
    const RuleSetData& d = *rs.data;
    std::string out;
    if (verdict == nullptr) out.reserve(1024);

    // ---- 1. validate the input --------------------------------------------------------------------------
    size_t total_bytes = in.text_len;
    for (const FieldIn& f : in.fields) total_bytes += f.value.size();
    if (in.text_len > cfg.limits.max_text_bytes) {
        write_error_result(rs, cfg, in, "input_too_large",
                           "text of " + std::to_string(in.text_len) + " bytes exceeds limits.max_text_bytes", in.text_len,
                           elapsed_us(), out, verdict);
        return out;
    }
    for (const FieldIn& f : in.fields) {
        if (f.value.size() > cfg.limits.max_text_bytes) {
            write_error_result(rs, cfg, in, "input_too_large", "field '" + f.name + "' exceeds limits.max_text_bytes",
                               total_bytes, elapsed_us(), out, verdict);
            return out;
        }
    }
    size_t bad = 0;
    if (in.text_len > 0 && !utf8_valid(reinterpret_cast<const uint8_t*>(in.text), in.text_len, &bad)) {
        write_error_result(rs, cfg, in, "invalid_utf8", "text is not valid UTF-8 (first bad byte at offset " + std::to_string(bad) + ")",
                           total_bytes, elapsed_us(), out, verdict);
        return out;
    }
    for (const FieldIn& f : in.fields) {
        if (!utf8_valid(reinterpret_cast<const uint8_t*>(f.value.data()), f.value.size(), &bad)) {
            write_error_result(rs, cfg, in, "invalid_utf8", "field '" + f.name + "' is not valid UTF-8", total_bytes,
                               elapsed_us(), out, verdict);
            return out;
        }
    }

    std::vector<std::string> warnings;
    auto warn = [&](const std::string& w) {
        if (warnings.size() < 20) warnings.push_back(w);
    };

    // ---- 2. targets: which text supplies which rule field ------------------------------------------------
    const std::string source = in.source.empty() ? "user_input" : in.source;
    std::vector<Target> targets;
    targets.reserve(1 + in.fields.size());
    const size_t n_words = (d.patterns.size() + 63) / 64;
    std::vector<int> primary_fields;
    {
        auto it = d.source_fields.find(source);
        if (it != d.source_fields.end()) {
            primary_fields = it->second;
        } else {
            const int content = d.field_index("content");
            if (content >= 0) primary_fields.push_back(content);
            warn("unknown_source:" + source + " (only generic 'content' rules were applied)");
        }
    }
    std::vector<int> field_target(d.fields.size(), -1);
    std::vector<std::string> ignored_fields;
    std::vector<int> named_targets;
    for (const FieldIn& f : in.fields) {
        const int fi = d.field_index(f.name);
        if (fi < 0) {
            ignored_fields.push_back(f.name);        // no rule reads this field: it is NOT checked
            continue;
        }
        Target t;
        t.name = f.name;
        t.text = f.value.data();
        t.len = f.value.size();
        t.fields.push_back(fi);
        t.bits.assign(n_words, 0);
        targets.push_back(std::move(t));
        field_target[static_cast<size_t>(fi)] = static_cast<int>(targets.size()) - 1;
    }
    if (in.text_len > 0 || in.fields.empty()) {
        Target t;
        t.text = in.text != nullptr ? in.text : "";
        t.len = in.text_len;
        for (int fi : primary_fields) {
            if (field_target[static_cast<size_t>(fi)] < 0) t.fields.push_back(fi);   // explicit named fields win
        }
        t.bits.assign(n_words, 0);
        targets.push_back(std::move(t));
        const int ti = static_cast<int>(targets.size()) - 1;
        for (int fi : targets.back().fields) field_target[static_cast<size_t>(fi)] = ti;
    }

    // ---- 3. scan every target with every profile ------------------------------------------------------------
    const bool want_offsets = cfg.output.include_offsets || cfg.output.include_evidence_text || (verdict != nullptr && verdict->hits_cap > 0);
    bool hit_limit = false, verify_failed = false;
    std::vector<Candidate> cands;
    for (Target& t : targets) {
        if (t.len == 0) continue;
        for (size_t pi = 0; pi < d.profiles.size(); ++pi) {
            if (d.profile_pattern_count[pi] == 0) continue;
            unsigned done = 0;                                // bit mask of the effective views already scanned for this profile
            for (ViewKind vk : d.profiles[pi].views) {
                const char* vdata = nullptr;
                size_t vlen = 0;
                const bool changed = get_view(t, vk, want_offsets, &vdata, &vlen);
                const ViewKind eff = changed ? vk : ViewKind::Raw;
                if ((done >> static_cast<int>(eff)) & 1u) continue;
                done |= 1u << static_cast<int>(eff);
                t.views_scanned |= 1u << static_cast<int>(eff);
                if (vlen == 0) continue;
                cands.clear();
                sc.backend->exec_errors.clear();
                if (!rs.backend->scan(static_cast<int>(pi), vdata, vlen, *sc.backend, cands, cfg.limits.max_hits)) hit_limit = true;
                for (const Candidate& c : cands) {
                    uint64_t end = c.end;
                    if (!c.exact) {
                        const uint32_t pid = d.patterns[c.pattern_index].id;
                        if (!rs.verifier || !rs.verifier->has(static_cast<int>(c.pattern_index)) || !sc.verify) {
                            warn("unverifiable_candidate:" + std::to_string(pid));
                            verify_failed = true;
                            continue;
                        }
                        if (elapsed_us() > cfg.limits.verify_budget_us) {
                            warn("verify_budget_exceeded:" + std::to_string(pid));
                            verify_failed = true;
                            continue;
                        }
                        int perr = 0;
                        const Pcre2Set::Result r = rs.verifier->match(static_cast<int>(c.pattern_index), vdata, vlen, *sc.verify, &end, &perr);
                        if (r == Pcre2Set::Result::NoMatch) continue;
                        if (r == Pcre2Set::Result::Error) {
                            warn("pcre2_limit:" + std::to_string(pid) + ":" + Pcre2Set::error_message(perr));
                            verify_failed = true;
                            continue;
                        }
                    }
                    if (!t.has_hit(c.pattern_index)) {
                        t.bits[c.pattern_index >> 6] |= (1ull << (c.pattern_index & 63));
                        HitInfo h;
                        h.pattern_index = c.pattern_index;
                        h.view = static_cast<int>(eff);
                        h.end_view = end;
                        h.end_original = original_end(t, eff, changed, end);
                        t.hits.push_back(h);
                    }
                }
                for (const auto& e : sc.backend->exec_errors) {
                    warn("pcre2_limit:" + std::to_string(d.patterns[e.first].id) + ":" + Pcre2Set::error_message(e.second));
                    verify_failed = true;
                }
            }
        }
    }
    if (hit_limit) {
        write_error_result(rs, cfg, in, "hit_limit_exceeded", "more than limits.max_hits candidate matches in one view",
                           total_bytes, elapsed_us(), out, verdict);
        return out;
    }

    // ---- 4. rule conditions (three-valued) + context gating ----------------------------------------------------
    const double mult = d.scoring.multiplier_for(source);
    std::vector<Matched> matched;
    std::vector<NeedsCtx> needs;
    std::vector<int8_t> vals;
    vals.reserve(64);
    std::vector<const std::string*> missing_ctx;               // reused for every rule
    std::vector<int> missing_field_idx;                       // reused for every rule: no allocation on the common path
    for (const RuleDef& r : d.rules) {
        // context gate
        int ctx_state = 0;                                   // 0 ok, 1 missing, 2 mismatch
        missing_ctx.clear();
        for (const auto& req : r.context_requires) {
            const std::pair<std::string, std::string>* found = nullptr;
            for (const auto& kv : in.context) {
                if (kv.first == req.first) {
                    found = &kv;
                    break;
                }
            }
            if (found == nullptr) {
                ctx_state = std::max(ctx_state, 1);
                missing_ctx.push_back(&req.first);
            } else if (found->second != req.second) {
                ctx_state = 2;
                break;
            }
        }
        if (ctx_state == 2) continue;

        missing_field_idx.clear();
        const int8_t truth = eval_rule(r, vals, [&](const LeafDef& lf) -> int8_t {
            const int ti = field_target[static_cast<size_t>(lf.field)];
            if (ti < 0) {
                if (std::find(missing_field_idx.begin(), missing_field_idx.end(), lf.field) == missing_field_idx.end()) missing_field_idx.push_back(lf.field);
                return kUnknown;
            }
            return targets[static_cast<size_t>(ti)].has_hit(static_cast<uint32_t>(lf.pattern)) ? kTrue : kFalse;
        });
        if (truth == kFalse) continue;          // cannot be satisfied: no evidence to collect
        // evidence: leaves that matched
        std::vector<uint32_t> pids;
        std::vector<std::pair<const Target*, uint32_t>> evid;
        std::vector<std::string> evid_fields;
        for (const LeafDef& lf : r.leaves) {
            const int ti = field_target[static_cast<size_t>(lf.field)];
            if (ti >= 0 && targets[static_cast<size_t>(ti)].has_hit(static_cast<uint32_t>(lf.pattern))) {
                const uint32_t pid = d.patterns[static_cast<size_t>(lf.pattern)].id;
                if (std::find(pids.begin(), pids.end(), pid) == pids.end()) pids.push_back(pid);
                evid.emplace_back(&targets[static_cast<size_t>(ti)], static_cast<uint32_t>(lf.pattern));
                evid_fields.push_back(d.fields[static_cast<size_t>(lf.field)]);
            }
        }
        std::sort(pids.begin(), pids.end());
        double risk = r.weight * r.confidence * mult;
        if (risk < 0.0) risk = 0.0;
        if (risk > 1.0) risk = 1.0;
        if (truth == kTrue && ctx_state == 0) {
            Matched m;
            m.rule = &r;
            m.pattern_ids = std::move(pids);
            m.evidence = std::move(evid);
            m.evidence_fields = std::move(evid_fields);
            m.risk = risk;
            m.counted = true;
            matched.push_back(std::move(m));
        } else if (truth == kTrue && ctx_state == 1) {
            NeedsCtx n;
            n.rule = &r;
            n.reason = "context_missing";
            for (const std::string* m : missing_ctx) n.missing.push_back(*m);
            std::sort(n.missing.begin(), n.missing.end());
            n.pattern_ids = std::move(pids);
            n.risk = risk;
            needs.push_back(std::move(n));
        } else if (truth == kUnknown && !pids.empty()) {
            NeedsCtx n;
            n.rule = &r;
            n.reason = "field_missing";
            for (int fi : missing_field_idx) n.missing.push_back(d.fields[static_cast<size_t>(fi)]);
            std::sort(n.missing.begin(), n.missing.end());
            n.pattern_ids = std::move(pids);
            n.risk = risk;
            needs.push_back(std::move(n));
        }
    }

    // ---- 5. score and decision -------------------------------------------------------------------------------
    {   // mark rules that do not count because another rule of the same score group has a higher risk
        std::map<std::string, size_t> best;
        for (size_t i = 0; i < matched.size(); ++i) {
            const std::string& g = matched[i].rule->score_group;
            if (g.empty()) continue;
            auto it = best.find(g);
            if (it == best.end()) best[g] = i;
            else if (matched[i].risk > matched[it->second].risk) best[g] = i;
        }
        for (size_t i = 0; i < matched.size(); ++i) {
            const std::string& g = matched[i].rule->score_group;
            if (!g.empty() && best[g] != i) matched[i].counted = false;
        }
    }
    std::vector<double> risks, potential_risks;
    std::vector<std::string> groups, potential_groups;
    for (const Matched& m : matched) {
        risks.push_back(m.risk);
        groups.push_back(m.rule->score_group);
        potential_risks.push_back(m.risk);
        potential_groups.push_back(m.rule->score_group);
    }
    for (const NeedsCtx& n : needs) {
        potential_risks.push_back(n.risk);
        potential_groups.push_back(n.rule->score_group);
    }
    const double score = matched.empty() ? 0.0 : combine(risks, groups);
    const double potential = combine(potential_risks, potential_groups);
    double th_review = d.scoring.review, th_alert = d.scoring.alert, th_block = d.scoring.block;
    if (cfg.policy.override_review) th_review = cfg.policy.review;
    if (cfg.policy.override_alert) th_alert = cfg.policy.alert;
    if (cfg.policy.override_block) th_block = cfg.policy.block;
    double th_needs_context = d.scoring.needs_context_review_at;
    if (cfg.policy.override_needs_context) th_needs_context = cfg.policy.needs_context_review_at;

    std::string decision = "allow";
    if (score >= th_alert && !matched.empty()) {
        decision = (cfg.policy.allow_block && score >= th_block) ? "block" : "alert";
    } else if ((score >= th_review && !matched.empty()) ||
               (!needs.empty() && potential >= th_needs_context)) {
        decision = "review";
    }
    if (verify_failed && cfg.policy.on_verify_error == "review" && decision == "allow") decision = "review";
    std::string risk_level = "none";
    if (!matched.empty()) {
        risk_level = "info";
        for (const auto& lv : d.scoring.risk_levels) {
            if (score >= lv.second) {
                risk_level = lv.first;
                break;
            }
        }
    }
    std::sort(matched.begin(), matched.end(), [](const Matched& a, const Matched& b) {
        if (a.risk != b.risk) return a.risk > b.risk;
        return a.rule->id < b.rule->id;
    });
    if (verdict != nullptr) {
        verdict->decision = decision_code(decision);
        verdict->scan_error = false;
        verdict->score = score;
        verdict->matched_rules = static_cast<uint32_t>(matched.size());
        for (size_t i = 0; verdict->hits != nullptr && i < matched.size() && i < verdict->hits_cap; ++i) {
            HitOut& ho = verdict->hits[i];
            std::snprintf(ho.rule_id, sizeof ho.rule_id, "%s", matched[i].rule->id.c_str());
            ho.matched_text[0] = '\0';
            for (const auto& ev : matched[i].evidence) {
                const Target* t = ev.first;
                const HitInfo* h = t->hit_info(ev.second);
                Span sp;
                if (h == nullptr || !locate_span(rs, sc, *t, *h, &sp)) continue;
                size_t take = static_cast<size_t>(sp.eo - sp.so);
                if (take > sizeof ho.matched_text - 1) take = utf8_floor(t->text + sp.so, t->len - static_cast<size_t>(sp.so), sizeof ho.matched_text - 1);
                std::memcpy(ho.matched_text, t->text + sp.so, take);
                ho.matched_text[take] = '\0';
                break;
            }
        }
        return out;
    }
    const uint64_t duration_us = elapsed_us();

    // ---- 6. JSON ------------------------------------------------------------------------------------------------
    JsonWriter w(out);
    w.begin_object();
    w.kv_int("schema_version", 1);
    w.key("request_id");
    if (in.has_request_id) w.value_string(in.request_id); else w.value_null();
    w.kv_string("status", "ok");
    w.kv_string("decision", decision);
    w.kv_double("score", score);
    w.kv_string("risk_level", risk_level);
    w.kv_string("ruleset_version", d.version);
    w.kv_string("engine_version", APG_ENGINE_VERSION);
    w.kv_string("backend", rs.backend->name());
    w.key("matched_rules");
    w.begin_array();
    for (const Matched& m : matched) {
        w.begin_object();
        w.kv_string("rule_id", m.rule->id);
        w.key("pattern_ids");
        w.begin_array();
        for (uint32_t pid : m.pattern_ids) w.value_uint(pid);
        w.end_array();
        w.kv_string("category", m.rule->category);
        w.kv_string("severity", m.rule->severity);
        w.kv_string("source", source);
        w.kv_double("confidence", m.rule->confidence, 4);
        w.kv_double("weight", m.rule->weight, 4);
        w.kv_double("risk", m.risk);
        w.kv_bool("counted", m.counted);
        if (cfg.output.include_names) w.kv_string("name", m.rule->name);
        if (cfg.output.include_offsets) {
            w.key("evidence");
            w.begin_array();
            for (size_t i = 0; i < m.evidence.size(); ++i) {
                const Target* t = m.evidence[i].first;
                const HitInfo* h = t->hit_info(m.evidence[i].second);
                if (h == nullptr) continue;
                w.begin_object();
                w.kv_uint("pattern_id", d.patterns[m.evidence[i].second].id);
                w.kv_string("field", m.evidence_fields[i]);
                w.kv_string("view", view_name(static_cast<ViewKind>(h->view)));
                w.kv_uint("end_view", h->end_view);
                w.kv_uint("end_original", h->end_original);
                if (cfg.output.include_evidence_text) emit_evidence_text(w, rs, sc, *t, *h);
                w.end_object();
            }
            w.end_array();
        }
        w.end_object();
    }
    w.end_array();
    w.key("needs_context");
    w.begin_array();
    for (const NeedsCtx& n : needs) {
        w.begin_object();
        w.kv_string("rule_id", n.rule->id);
        w.kv_string("category", n.rule->category);
        w.kv_string("severity", n.rule->severity);
        w.kv_string("reason", n.reason);
        w.key("missing");
        w.begin_array();
        for (const std::string& m : n.missing) w.value_string(m);
        w.end_array();
        w.key("pattern_ids");
        w.begin_array();
        for (uint32_t pid : n.pattern_ids) w.value_uint(pid);
        w.end_array();
        w.end_object();
    }
    w.end_array();
    w.key("inputs");
    w.begin_object();
    w.kv_uint("text_bytes", total_bytes);
    w.key("fields_checked");
    w.begin_array();
    {
        std::set<std::string> names;
        for (const Target& t : targets) {
            for (int fi : t.fields) names.insert(d.fields[static_cast<size_t>(fi)]);
        }
        for (const std::string& n : names) w.value_string(n);
    }
    w.end_array();
    w.key("fields_ignored");
    w.begin_array();
    for (const std::string& n : ignored_fields) w.value_string(n);
    w.end_array();
    w.key("views_scanned");
    w.begin_array();
    {
        unsigned views = 0;
        for (const Target& t : targets) views |= t.views_scanned;
        for (int v = 0; v < kViewKindCount; ++v) {
            if ((views >> v) & 1u) w.value_string(view_name(static_cast<ViewKind>(v)));
        }
    }
    w.end_array();
    w.end_object();
    w.key("warnings");
    w.begin_array();
    for (const std::string& s : warnings) w.value_string(s);
    w.end_array();
    w.kv_uint("duration_us", duration_us);
    w.key("error_code");
    w.value_null();
    w.end_object();
    return out;
}

// ---- first match -----------------------------------------------------------------------------------------------------
namespace {

// Handles the candidates of the running scan: confirms them with PCRE2 where needed, records the hit and decides at once whether
// a rule became true. Returning true ends the Hyperscan scan.
class FirstMatchSink : public CandidateSink {
public:
    FirstMatchSink(const LoadedRuleset& rs, const Config& cfg, ThreadScratch& sc, Target& t, const std::vector<int>& primary_fields,
                   double mult, double min_risk, std::chrono::steady_clock::time_point t0)
        : rs_(rs), d_(*rs.data), cfg_(cfg), sc_(sc), t_(t), primary_(primary_fields), mult_(mult), min_risk_(min_risk), t0_(t0) {
        vals_.reserve(64);
    }

    // The view that is being scanned.
    void set_view(const char* data, size_t len, ViewKind eff, bool changed) {
        vdata_ = data; vlen_ = len; eff_ = eff; changed_ = changed;
    }

    bool on_candidate(const Candidate& c) override {
        if (t_.has_hit(c.pattern_index)) return false;
        uint64_t end = c.end;
        if (!c.exact) {
            if (!rs_.verifier || !rs_.verifier->has(static_cast<int>(c.pattern_index)) || !sc_.verify) return false;
            const auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0_).count();
            if (static_cast<uint64_t>(us) > cfg_.limits.verify_budget_us) return false;
            int perr = 0;
            if (rs_.verifier->match(static_cast<int>(c.pattern_index), vdata_, vlen_, *sc_.verify, &end, &perr) != Pcre2Set::Result::Match) return false;
        }
        t_.bits[c.pattern_index >> 6] |= (1ull << (c.pattern_index & 63));
        HitInfo h;
        h.pattern_index = c.pattern_index;
        h.view = static_cast<int>(eff_);
        h.end_view = end;
        h.end_original = original_end(t_, eff_, changed_, end);
        t_.hits.push_back(h);
        for (int ri : d_.early_rules_by_pattern[c.pattern_index]) {
            if (qualifies(d_.rules[static_cast<size_t>(ri)])) {
                rule_ = &d_.rules[static_cast<size_t>(ri)];
                return true;
            }
        }
        return false;
    }

    // True if the rule is satisfied by the hits so far and its risk reaches min_risk.
    bool qualifies(const RuleDef& r) {
        const int8_t truth = eval_rule(r, vals_, [&](const LeafDef& lf) -> int8_t {
            if (!supplied(lf.field)) return kUnknown;
            return t_.has_hit(static_cast<uint32_t>(lf.pattern)) ? kTrue : kFalse;
        });
        if (truth != kTrue) return false;
        double risk = r.weight * r.confidence * mult_;
        if (risk > 1.0) risk = 1.0;
        return risk >= min_risk_;
    }

    const RuleDef* rule() const { return rule_; }

private:
    bool supplied(int field) const {
        for (int f : primary_) {
            if (f == field) return true;
        }
        return false;
    }

    const LoadedRuleset& rs_;
    const RuleSetData& d_;
    const Config& cfg_;
    ThreadScratch& sc_;
    Target& t_;
    const std::vector<int>& primary_;
    double mult_, min_risk_;
    std::chrono::steady_clock::time_point t0_;
    std::vector<int8_t> vals_;
    const char* vdata_ = nullptr;
    size_t vlen_ = 0;
    ViewKind eff_ = ViewKind::Raw;
    bool changed_ = false;
    const RuleDef* rule_ = nullptr;
};

}  // namespace

void run_first_match(const LoadedRuleset& rs, const Config& cfg, const char* text, size_t len, const char* source, double min_risk,
                     ThreadScratch& sc, MatchOut* out) {
    std::memset(out, 0, sizeof *out);
    const auto t_start = std::chrono::steady_clock::now();
    const RuleSetData& d = *rs.data;
    if (len == 0) return;
    size_t bad = 0;
    if (len > cfg.limits.max_text_bytes || !utf8_valid(reinterpret_cast<const uint8_t*>(text), len, &bad)) {
        out->scan_error = 1;
        return;
    }
    const std::string src = (source == nullptr || source[0] == '\0') ? std::string("user_input") : std::string(source);
    std::vector<int> content_only;
    const std::vector<int>* primary = nullptr;
    {
        auto it = d.source_fields.find(src);
        if (it != d.source_fields.end()) {
            primary = &it->second;
        } else {
            const int content = d.field_index("content");
            if (content >= 0) content_only.push_back(content);
            primary = &content_only;
        }
    }
    Target t;
    t.text = text;
    t.len = len;
    t.bits.assign((d.patterns.size() + 63) / 64, 0);
    FirstMatchSink sink(rs, cfg, sc, t, *primary, d.scoring.multiplier_for(src), min_risk, t_start);

    bool hit_limit = false;
    std::vector<Candidate> unused;                                      // the sink takes the candidates; nothing is appended
    for (size_t pi = 0; pi < d.profiles.size() && sink.rule() == nullptr; ++pi) {
        if (d.profile_pattern_count[pi] == 0) continue;
        unsigned done = 0;
        for (ViewKind vk : d.profiles[pi].views) {
            const char* vdata = nullptr;
            size_t vlen = 0;
            const bool changed = get_view(t, vk, false, &vdata, &vlen);
            const ViewKind eff = changed ? vk : ViewKind::Raw;
            if ((done >> static_cast<int>(eff)) & 1u) continue;
            done |= 1u << static_cast<int>(eff);
            if (vlen == 0) continue;
            sink.set_view(vdata, vlen, eff, changed);
            sc.backend->exec_errors.clear();
            if (!rs.backend->scan(static_cast<int>(pi), vdata, vlen, *sc.backend, unused, cfg.limits.max_hits, &sink)) {
                hit_limit = true;
                break;
            }
            if (sink.rule() != nullptr) break;
        }
    }
    if (hit_limit) {
        out->scan_error = 1;
        return;
    }
    const RuleDef* hit_rule = sink.rule();
    if (hit_rule == nullptr) {                                          // rules with a `not` can only be decided once everything was scanned
        for (int ri : d.late_rules) {
            if (sink.qualifies(d.rules[static_cast<size_t>(ri)])) {
                hit_rule = &d.rules[static_cast<size_t>(ri)];
                break;
            }
        }
    }
    if (hit_rule == nullptr) return;

    out->matched = 1;
    std::strncpy(out->rule_id, hit_rule->id.c_str(), sizeof out->rule_id - 1);
    // matched_text: the first leaf of the rule that hit
    for (const LeafDef& lf : hit_rule->leaves) {
        if (!t.has_hit(static_cast<uint32_t>(lf.pattern))) continue;
        const HitInfo* hi = t.hit_info(static_cast<uint32_t>(lf.pattern));
        if (hi == nullptr) continue;
        if (hi->view != static_cast<int>(ViewKind::Raw)) {              // offsets back to the original text are recorded only on request
            Normalized& n = t.norm[hi->view];
            if (n.offsets.size() != n.text.size() + 1) normalize(static_cast<ViewKind>(hi->view), reinterpret_cast<const uint8_t*>(text), len, true, n);
        }
        Span sp;
        if (!locate_span(rs, sc, t, *hi, &sp)) break;
        size_t take = static_cast<size_t>(sp.eo - sp.so);
        if (take > sizeof out->matched_text - 1) take = utf8_floor(text + sp.so, len - static_cast<size_t>(sp.so), sizeof out->matched_text - 1);
        std::memcpy(out->matched_text, text + sp.so, take);
        break;
    }
}

}  // namespace apg
