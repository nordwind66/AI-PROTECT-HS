// Read-only access to the authoritative SQLite rule database (used by the CLI / compiler only; the runtime
// library never opens SQLite). All writes to the database go through tools/rules.py so that the audit chain
// and the Python-side invariants stay in one place.
#pragma once

#include <string>
#include <utility>
#include <vector>

#include "../core/common.h"

struct sqlite3;

namespace apg {

struct SnapshotRow {
    int version_id = 0;
    std::string version;
    std::string status;
    std::string body;                 // exact snapshot bytes (JSON)
    std::string sha256_recorded;      // sha256 stored next to the body
    std::string sha256_in_version;    // ruleset_versions.snapshot_sha256
    std::string content_digest;
    int rule_count = 0;
    int pattern_count = 0;
};

struct VersionRow {
    std::string version, status, content_digest, published_at;
    int rule_count = 0, pattern_count = 0, artifacts = 0;
    bool active = false;
};

class SqliteStore {
public:
    // Opens READ-ONLY. Throws Error(Status::Database) with sqlite's message on failure.
    explicit SqliteStore(const std::string& utf8_path);
    ~SqliteStore();
    SqliteStore(const SqliteStore&) = delete;
    SqliteStore& operator=(const SqliteStore&) = delete;

    int schema_version();
    // Throws if the version does not exist or is not published.
    SnapshotRow load_published_snapshot(const std::string& version);
    std::vector<VersionRow> list_versions();
    // "source_id:source_key" strings explaining where a pattern came from (for build failure reports).
    std::vector<std::string> provenance_of_pattern(uint32_t pattern_id);

private:
    sqlite3* db_ = nullptr;
};

}  // namespace apg
