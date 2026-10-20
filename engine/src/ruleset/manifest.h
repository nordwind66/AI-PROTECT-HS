// Manifest handling: verification of a compiled rule-set directory and construction of a LoadedRuleset.
//
// manifest.json ties together (all checked at load time, any mismatch is an error, never a silent mix):
//   * the exact snapshot (ruleset.meta.json, sha256, version, content digest),
//   * one serialised Hyperscan database per normalisation profile (sha256 each),
//   * the platform it was compiled for (os / arch / Hyperscan version / CPU features),
//   * its own build_hash (sha256 of the canonical manifest without that field).
#pragma once

#include <memory>
#include <string>

#include "../core/config.h"
#include "../core/json.h"
#include "loaded_ruleset.h"

namespace apg {

// Loads and verifies the rule set referenced by `manifest_path_utf8`. The path may also name an
// "apg-active-pointer" document (dist/<os>/<arch>/active.json), which is resolved first.
// Throws Error with the status code that apg_create / apg_reload report.
std::shared_ptr<LoadedRuleset> load_ruleset(const std::string& manifest_path_utf8, const Config& cfg);

// sha256 over json_dump_canonical(manifest without "build_hash").
std::string manifest_build_hash(const Json& manifest);

// Resolves `relative` inside `base_dir`; throws Error(Status::Database) for absolute paths or "..".
std::string resolve_inside(const std::string& base_dir, const std::string& relative);

}  // namespace apg
