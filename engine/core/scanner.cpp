#include "scanner.h"

#include <algorithm>
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
    std::set<int> views_scanned;

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
                        const std::string& detail, size_t text_bytes, uint64_t duration_us, std::string& out) {
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

std::string run_scan(const LoadedRuleset& rs, const Config& cfg, const ScanInput& in, ThreadScratch& sc) {
    const auto t_start = std::chrono::steady_clock::now();
    auto elapsed_us = [&]() -> uint64_t {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                         std::chrono::steady_clock::now() - t_start).count());
    };
    const RuleSetData& d = *rs.data;
    std::string out;
    out.reserve(1024);

    // ---- 1. validate the input --------------------------------------------------------------------------
    size_t total_bytes = in.text_len;
    for (const FieldIn& f : in.fields) total_bytes += f.value.size();
    if (in.text_len > cfg.limits.max_text_bytes) {
        write_error_result(rs, cfg, in, "input_too_large",
                           "text of " + std::to_string(in.text_len) + " bytes exceeds limits.max_text_bytes", in.text_len,
                           elapsed_us(), out);
        return out;
    }
    for (const FieldIn& f : in.fields) {
        if (f.value.size() > cfg.limits.max_text_bytes) {
            write_error_result(rs, cfg, in, "input_too_large", "field '" + f.name + "' exceeds limits.max_text_bytes",
                               total_bytes, elapsed_us(), out);
            return out;
        }
    }
    size_t bad = 0;
    if (in.text_len > 0 && !utf8_valid(reinterpret_cast<const uint8_t*>(in.text), in.text_len, &bad)) {
        write_error_result(rs, cfg, in, "invalid_utf8", "text is not valid UTF-8 (first bad byte at offset " + std::to_string(bad) + ")",
                           total_bytes, elapsed_us(), out);
        return out;
    }
    for (const FieldIn& f : in.fields) {
        if (!utf8_valid(reinterpret_cast<const uint8_t*>(f.value.data()), f.value.size(), &bad)) {
            write_error_result(rs, cfg, in, "invalid_utf8", "field '" + f.name + "' is not valid UTF-8", total_bytes,
                               elapsed_us(), out);
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
    const bool want_offsets = cfg.output.include_offsets;
    bool hit_limit = false, verify_failed = false;
    std::vector<Candidate> cands;
    for (Target& t : targets) {
        if (t.len == 0) continue;
        for (size_t pi = 0; pi < d.profiles.size(); ++pi) {
            if (d.profile_pattern_count[pi] == 0) continue;
            std::set<int> done;                               // effective views already scanned for this profile
            for (ViewKind vk : d.profiles[pi].views) {
                const char* vdata = nullptr;
                size_t vlen = 0;
                const bool changed = get_view(t, vk, want_offsets, &vdata, &vlen);
                const ViewKind eff = changed ? vk : ViewKind::Raw;
                if (!done.insert(static_cast<int>(eff)).second) continue;
                t.views_scanned.insert(static_cast<int>(eff));
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
                           total_bytes, elapsed_us(), out);
        return out;
    }

    // ---- 4. rule conditions (three-valued) + context gating ----------------------------------------------------
    const double mult = d.scoring.multiplier_for(source);
    std::vector<Matched> matched;
    std::vector<NeedsCtx> needs;
    std::vector<int8_t> vals;
    for (const RuleDef& r : d.rules) {
        // context gate
        int ctx_state = 0;                                   // 0 ok, 1 missing, 2 mismatch
        std::vector<std::string> missing_ctx;
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
                missing_ctx.push_back(req.first);
            } else if (found->second != req.second) {
                ctx_state = 2;
                break;
            }
        }
        if (ctx_state == 2) continue;

        vals.assign(r.nodes.size(), static_cast<int8_t>(kFalse));
        std::vector<std::string> missing_fields;
        for (size_t ni = 0; ni < r.nodes.size(); ++ni) {          // children always precede their parent
            const CondNode& n = r.nodes[ni];
            int8_t v = kFalse;
            if (n.op == CondNode::Leaf) {
                const LeafDef& lf = r.leaves[static_cast<size_t>(n.leaf)];
                const int ti = field_target[static_cast<size_t>(lf.field)];
                if (ti < 0) {
                    v = kUnknown;
                    const std::string& fname = d.fields[static_cast<size_t>(lf.field)];
                    if (std::find(missing_fields.begin(), missing_fields.end(), fname) == missing_fields.end()) missing_fields.push_back(fname);
                } else {
                    v = targets[static_cast<size_t>(ti)].has_hit(static_cast<uint32_t>(lf.pattern)) ? kTrue : kFalse;
                }
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
        const int8_t truth = vals[static_cast<size_t>(r.root)];
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
            std::sort(missing_ctx.begin(), missing_ctx.end());
            n.missing = missing_ctx;
            n.pattern_ids = std::move(pids);
            n.risk = risk;
            needs.push_back(std::move(n));
        } else if (truth == kUnknown && !pids.empty()) {
            NeedsCtx n;
            n.rule = &r;
            n.reason = "field_missing";
            std::sort(missing_fields.begin(), missing_fields.end());
            n.missing = missing_fields;
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
        std::set<int> views;
        for (const Target& t : targets) views.insert(t.views_scanned.begin(), t.views_scanned.end());
        for (int v : views) w.value_string(view_name(static_cast<ViewKind>(v)));
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

}  // namespace apg
