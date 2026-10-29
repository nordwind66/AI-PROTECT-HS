// In-memory, immutable representation of a published rule-set snapshot (ruleset.meta.json).
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../core/common.h"
#include "../core/normalize.h"

namespace apg {

enum class PatternClass { Native, Prefilter };
enum class RuleScope { General, TranslationOnly, ContextRequired };

enum PatternFlagBits : uint32_t { kFlagI = 1u, kFlagM = 2u, kFlagS = 4u, kFlagU = 8u };

struct PatternDef {
    uint32_t id = 0;
    std::string regex;        // canonical PCRE-compatible expression (UTF-8)
    uint32_t flags = 0;       // PatternFlagBits
    std::string flag_text;    // "i", "is", ... as in the snapshot
    int profile = 0;          // index into RuleSetData::profiles
    PatternClass cls = PatternClass::Native;
    std::string lang;
};

struct ProfileDef {
    std::string name;
    std::vector<ViewKind> views;
};

struct LeafDef {
    std::string id;
    int pattern = -1;         // index into RuleSetData::patterns
    int field = -1;           // index into RuleSetData::fields
};

struct CondNode {
    enum Op { Leaf, Any, All, Not };
    Op op = Any;
    int leaf = -1;            // for Leaf: index into RuleDef::leaves
    std::vector<int> kids;    // indices into RuleDef::nodes
};

struct RuleDef {
    std::string id;
    int revision = 0;
    std::string name, category, lang, severity;
    double weight = 0, confidence = 0;
    std::string action;
    RuleScope scope = RuleScope::General;
    std::vector<std::pair<std::string, std::string>> context_requires;   // key -> required scalar (string form)
    std::string score_group;                                              // empty = none
    std::vector<LeafDef> leaves;
    std::vector<CondNode> nodes;
    int root = -1;
};

struct ScoringDef {
    double review = 0.30, alert = 0.50, block = 0.85;
    double needs_context_review_at = 0.50;
    // multiplier per source name (user_input, tool_output, rag_document, agent_message)
    std::vector<std::pair<std::string, double>> source_multiplier;
    std::vector<std::pair<std::string, double>> risk_levels;              // (name, lower bound), descending
    double multiplier_for(const std::string& source) const {
        for (const auto& kv : source_multiplier) {
            if (kv.first == source) return kv.second;
        }
        return 1.0;
    }
};

struct RuleSetData {
    std::string version, content_digest, source_digest;
    std::vector<std::string> fields;                          // interned field names
    std::map<std::string, std::vector<int>> source_fields;    // source -> field indexes it supplies
    std::vector<ProfileDef> profiles;
    std::vector<PatternDef> patterns;
    std::vector<int> profile_pattern_count;                   // patterns per profile (0 = nothing to scan)
    std::unordered_map<uint32_t, int> pattern_index_by_id;
    std::vector<RuleDef> rules;
    ScoringDef scoring;
    // For the first-match scan (apg_match_text), built once after parsing. Rules that need request context can never match there.
    std::vector<std::vector<int>> early_rules_by_pattern;     // pattern -> rules without `not` that can be decided the moment it hits
    std::vector<int> late_rules;                               // rules with a `not` node: decided after the whole text was scanned

    int field_index(const std::string& name) const {
        for (size_t i = 0; i < fields.size(); ++i) {
            if (fields[i] == name) return static_cast<int>(i);
        }
        return -1;
    }
    int profile_index(const std::string& name) const {
        for (size_t i = 0; i < profiles.size(); ++i) {
            if (profiles[i].name == name) return static_cast<int>(i);
        }
        return -1;
    }
};

// Parses the snapshot document. Throws Error(Status::Database / Status::Version) on any problem.
std::shared_ptr<RuleSetData> parse_snapshot(const std::string& bytes);

}  // namespace apg
