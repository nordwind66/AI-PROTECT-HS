#include "ruleset_model.h"

#include <set>

#include "../core/json.h"

namespace apg {

namespace {

[[noreturn]] void bad(const std::string& msg) { throw Error(Status::Database, "rule-set snapshot: " + msg); }

const Json& need(const Json& obj, const char* key) {
    const Json* v = obj.get(key);
    if (v == nullptr) bad(std::string("missing key '") + key + "'");
    return *v;
}

std::string scalar_to_string(const Json& v, const std::string& what) {
    switch (v.type()) {
        case Json::Type::String: return v.as_string();
        case Json::Type::Bool: return v.as_bool() ? "true" : "false";
        case Json::Type::Int: return std::to_string(v.as_int());
        default: bad(what + " must be a string, integer or boolean");
    }
}

int intern_field(RuleSetData& d, const std::string& name) {
    const int i = d.field_index(name);
    if (i >= 0) return i;
    d.fields.push_back(name);
    return static_cast<int>(d.fields.size()) - 1;
}

int build_node(const Json& j, RuleDef& rule, const std::map<std::string, int>& leaf_by_id, int depth) {
    if (depth > 32) bad("rule '" + rule.id + "': condition nesting too deep");
    const std::string& op = need(j, "op").as_string();
    CondNode node;
    if (op == "leaf") {
        const std::string& id = need(j, "id").as_string();
        auto it = leaf_by_id.find(id);
        if (it == leaf_by_id.end()) bad("rule '" + rule.id + "': condition references unknown leaf '" + id + "'");
        node.op = CondNode::Leaf;
        node.leaf = it->second;
    } else if (op == "any" || op == "all" || op == "not") {
        node.op = op == "any" ? CondNode::Any : op == "all" ? CondNode::All : CondNode::Not;
        const auto& args = need(j, "args").items();
        if (args.empty()) bad("rule '" + rule.id + "': '" + op + "' without arguments");
        if (node.op == CondNode::Not && args.size() != 1) bad("rule '" + rule.id + "': 'not' needs exactly one argument");
        for (const auto& a : args) node.kids.push_back(build_node(a, rule, leaf_by_id, depth + 1));
    } else {
        bad("rule '" + rule.id + "': unknown condition operator '" + op + "'");
    }
    rule.nodes.push_back(std::move(node));
    return static_cast<int>(rule.nodes.size()) - 1;
}

uint32_t parse_flags(const std::string& flags, uint32_t id) {
    uint32_t bits = 0;
    for (char c : flags) {
        if (c == 'i') bits |= kFlagI;
        else if (c == 'm') bits |= kFlagM;
        else if (c == 's') bits |= kFlagS;
        else if (c == 'u') bits |= kFlagU;
        else bad("pattern " + std::to_string(id) + ": unknown flag '" + std::string(1, c) + "'");
    }
    return bits;
}

}  // namespace

std::shared_ptr<RuleSetData> parse_snapshot(const std::string& bytes) {
    Json doc;
    try {
        doc = Json::parse(bytes, 64);
    } catch (const Error& e) {
        bad(e.what());
    }
    auto data = std::make_shared<RuleSetData>();
    try {
        if (need(doc, "format").as_string() != "apg-ruleset-snapshot") bad("not an apg-ruleset-snapshot document");
        if (need(doc, "format_version").as_int() != kSnapshotFormatVersion) {
            throw Error(Status::Version, "snapshot format version " + std::to_string(need(doc, "format_version").as_int()) +
                                             " is not supported by this engine");
        }
        const Json& rs = need(doc, "ruleset");
        data->version = need(rs, "version").as_string();
        data->content_digest = need(rs, "content_digest").as_string();
        if (const Json* sd = rs.get("source_digest")) data->source_digest = sd->as_string();

        const Json& norm = need(doc, "normalizer");
        if (need(norm, "tables_version").as_int() != static_cast<int64_t>(kNormTablesVersion)) {
            throw Error(Status::Version, "rule set was built for normalisation tables version " +
                                             std::to_string(need(norm, "tables_version").as_int()) + ", engine has " +
                                             std::to_string(kNormTablesVersion));
        }
        for (const auto& kv : need(norm, "profiles").members()) {
            ProfileDef p;
            p.name = kv.first;
            for (const auto& v : need(kv.second, "views").items()) {
                ViewKind k;
                if (!view_from_name(v.as_string(), &k)) {
                    throw Error(Status::Version, "profile '" + p.name + "' uses unknown view '" + v.as_string() + "'");
                }
                p.views.push_back(k);
            }
            if (p.views.empty()) bad("profile '" + p.name + "' has no views");
            data->profiles.push_back(std::move(p));
        }
        for (const auto& kv : need(doc, "field_map").members()) {
            std::vector<int> idx;
            for (const auto& f : kv.second.items()) idx.push_back(intern_field(*data, f.as_string()));
            data->source_fields[kv.first] = idx;
        }
        const Json& sc = need(doc, "scoring");
        const Json& th = need(sc, "thresholds");
        data->scoring.review = need(th, "review").as_double();
        data->scoring.alert = need(th, "alert").as_double();
        data->scoring.block = need(th, "block").as_double();
        data->scoring.needs_context_review_at = need(sc, "needs_context_review_at").as_double();
        for (const auto& kv : need(sc, "source_multiplier").members()) {
            data->scoring.source_multiplier.emplace_back(kv.first, kv.second.as_double());
        }
        for (const auto& lv : need(sc, "risk_levels").items()) {
            const auto& pair = lv.items();
            if (pair.size() != 2) bad("risk_levels entries must be [name, lower_bound]");
            data->scoring.risk_levels.emplace_back(pair[0].as_string(), pair[1].as_double());
        }

        for (const auto& pj : need(doc, "patterns").items()) {
            PatternDef p;
            const int64_t id = need(pj, "id").as_int();
            if (id < 1 || id > 4294967295LL) bad("pattern id out of range");
            p.id = static_cast<uint32_t>(id);
            if (data->pattern_index_by_id.count(p.id)) bad("duplicate pattern id " + std::to_string(p.id));
            p.regex = need(pj, "regex").as_string();
            p.flag_text = need(pj, "flags").as_string();
            p.flags = parse_flags(p.flag_text, p.id);
            const std::string& prof = need(pj, "profile").as_string();
            p.profile = data->profile_index(prof);
            if (p.profile < 0) bad("pattern " + std::to_string(p.id) + " uses undeclared profile '" + prof + "'");
            const std::string& cls = need(pj, "class").as_string();
            if (cls == "hs_native") p.cls = PatternClass::Native;
            else if (cls == "hs_prefilter_pcre2") p.cls = PatternClass::Prefilter;
            else bad("pattern " + std::to_string(p.id) + " has class '" + cls + "'");
            p.lang = need(pj, "lang").as_string();
            data->pattern_index_by_id[p.id] = static_cast<int>(data->patterns.size());
            data->patterns.push_back(std::move(p));
        }
        data->profile_pattern_count.assign(data->profiles.size(), 0);
        for (const PatternDef& p : data->patterns) ++data->profile_pattern_count[static_cast<size_t>(p.profile)];

        std::set<std::string> rule_ids;
        for (const auto& rj : need(doc, "rules").items()) {
            RuleDef r;
            r.id = need(rj, "id").as_string();
            if (!rule_ids.insert(r.id).second) bad("duplicate rule id " + r.id);
            r.revision = static_cast<int>(need(rj, "revision").as_int());
            r.name = need(rj, "name").as_string();
            r.category = need(rj, "category").as_string();
            r.lang = need(rj, "lang").as_string();
            r.severity = need(rj, "severity").as_string();
            r.weight = need(rj, "weight").as_double();
            r.confidence = need(rj, "confidence").as_double();
            r.action = need(rj, "action").as_string();
            const std::string& scope = need(rj, "scope").as_string();
            if (scope == "general") r.scope = RuleScope::General;
            else if (scope == "translation_only") r.scope = RuleScope::TranslationOnly;
            else if (scope == "context_required") r.scope = RuleScope::ContextRequired;
            else bad("rule " + r.id + ": unknown scope '" + scope + "'");
            const Json& cr = need(rj, "context_requires");
            if (!cr.is_null()) {
                for (const auto& kv : cr.members()) {
                    r.context_requires.emplace_back(kv.first, scalar_to_string(kv.second, "context_requires value"));
                }
            }
            const Json& sg = need(rj, "score_group");
            if (!sg.is_null()) r.score_group = sg.as_string();
            std::map<std::string, int> leaf_by_id;
            for (const auto& lj : need(rj, "leaves").items()) {
                LeafDef leaf;
                leaf.id = need(lj, "id").as_string();
                const int64_t pid = need(lj, "pattern_id").as_int();
                auto it = data->pattern_index_by_id.find(static_cast<uint32_t>(pid));
                if (pid < 1 || it == data->pattern_index_by_id.end()) {
                    bad("rule " + r.id + ": leaf '" + leaf.id + "' references unknown pattern " + std::to_string(pid));
                }
                leaf.pattern = it->second;
                leaf.field = intern_field(*data, need(lj, "field").as_string());
                if (leaf_by_id.count(leaf.id)) bad("rule " + r.id + ": duplicate leaf id '" + leaf.id + "'");
                leaf_by_id[leaf.id] = static_cast<int>(r.leaves.size());
                r.leaves.push_back(std::move(leaf));
            }
            r.root = build_node(need(rj, "condition"), r, leaf_by_id, 0);
            data->rules.push_back(std::move(r));
        }
    } catch (const Error&) {
        throw;
    }
    data->early_rules_by_pattern.assign(data->patterns.size(), std::vector<int>());
    for (size_t ri = 0; ri < data->rules.size(); ++ri) {
        const RuleDef& r = data->rules[ri];
        if (!r.context_requires.empty()) continue;
        bool has_not = false;
        for (const CondNode& n : r.nodes) has_not = has_not || n.op == CondNode::Not;
        if (has_not) {
            data->late_rules.push_back(static_cast<int>(ri));
            continue;
        }
        for (const LeafDef& lf : r.leaves) {
            std::vector<int>& v = data->early_rules_by_pattern[static_cast<size_t>(lf.pattern)];
            if (v.empty() || v.back() != static_cast<int>(ri)) v.push_back(static_cast<int>(ri));
        }
    }
    return data;
}

}  // namespace apg
