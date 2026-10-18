#include "sqlite_store.h"

#include <sqlite3.h>

#include "../core/sha256.h"

namespace apg {

namespace {

class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) : stmt_(nullptr) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK) {
            throw Error(Status::Database, std::string("sqlite: ") + sqlite3_errmsg(db) + " [" + sql + "]");
        }
        db_ = db;
    }
    ~Stmt() {
        if (stmt_ != nullptr) sqlite3_finalize(stmt_);
    }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    void bind_text(int idx, const std::string& v) { sqlite3_bind_text(stmt_, idx, v.c_str(), static_cast<int>(v.size()), SQLITE_TRANSIENT); }
    void bind_int(int idx, long long v) { sqlite3_bind_int64(stmt_, idx, v); }
    bool step() {
        const int rc = sqlite3_step(stmt_);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        throw Error(Status::Database, std::string("sqlite: ") + sqlite3_errmsg(db_));
    }
    std::string text(int col) {
        const unsigned char* p = sqlite3_column_text(stmt_, col);
        const int n = sqlite3_column_bytes(stmt_, col);
        return p == nullptr ? std::string() : std::string(reinterpret_cast<const char*>(p), static_cast<size_t>(n));
    }
    std::string blob(int col) {
        const void* p = sqlite3_column_blob(stmt_, col);
        const int n = sqlite3_column_bytes(stmt_, col);
        return p == nullptr ? std::string() : std::string(static_cast<const char*>(p), static_cast<size_t>(n));
    }
    long long int64(int col) { return sqlite3_column_int64(stmt_, col); }

private:
    sqlite3* db_ = nullptr;
    sqlite3_stmt* stmt_;
};

}  // namespace

SqliteStore::SqliteStore(const std::string& utf8_path) {
    const int rc = sqlite3_open_v2(utf8_path.c_str(), &db_, SQLITE_OPEN_READONLY, nullptr);
    if (rc != SQLITE_OK) {
        const std::string msg = db_ != nullptr ? sqlite3_errmsg(db_) : "cannot allocate sqlite handle";
        if (db_ != nullptr) sqlite3_close(db_);
        db_ = nullptr;
        throw Error(Status::Database, "cannot open rule database '" + utf8_path + "': " + msg);
    }
    sqlite3_busy_timeout(db_, 10000);
    sqlite3_exec(db_, "PRAGMA foreign_keys = ON", nullptr, nullptr, nullptr);
    try {
        if (schema_version() < 1) throw Error(Status::Database, "'" + utf8_path + "' is not an AI Prompt Guard rule database");
    } catch (...) {
        sqlite3_close(db_);
        db_ = nullptr;
        throw;
    }
}

SqliteStore::~SqliteStore() {
    if (db_ != nullptr) sqlite3_close(db_);
}

int SqliteStore::schema_version() {
    Stmt s(db_, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations");
    return s.step() ? static_cast<int>(s.int64(0)) : 0;
}

SnapshotRow SqliteStore::load_published_snapshot(const std::string& version) {
    Stmt s(db_,
           "SELECT v.version_id, v.version, v.status, s.body, s.sha256, v.snapshot_sha256, v.content_digest, v.rule_count, "
           "v.pattern_count FROM ruleset_versions v LEFT JOIN ruleset_snapshots s ON s.version_id = v.version_id "
           "WHERE v.version = ?");
    s.bind_text(1, version);
    if (!s.step()) throw Error(Status::Database, "rule-set version '" + version + "' does not exist in the database");
    SnapshotRow r;
    r.version_id = static_cast<int>(s.int64(0));
    r.version = s.text(1);
    r.status = s.text(2);
    r.body = s.blob(3);
    r.sha256_recorded = s.text(4);
    r.sha256_in_version = s.text(5);
    r.content_digest = s.text(6);
    r.rule_count = static_cast<int>(s.int64(7));
    r.pattern_count = static_cast<int>(s.int64(8));
    if (r.status != "published") {
        throw Error(Status::Database, "version '" + version + "' is '" + r.status + "': only published versions can be compiled");
    }
    if (r.body.empty()) throw Error(Status::Database, "version '" + version + "' has no stored snapshot");
    const std::string actual = sha256_hex(r.body);
    if (actual != r.sha256_recorded || actual != r.sha256_in_version) {
        throw Error(Status::Database, "snapshot of version '" + version + "' is corrupt: sha256 mismatch (computed " + actual + ")");
    }
    return r;
}

std::vector<VersionRow> SqliteStore::list_versions() {
    std::vector<VersionRow> out;
    Stmt s(db_,
           "SELECT v.version, v.status, COALESCE(v.content_digest,''), COALESCE(v.published_at, v.created_at), "
           "COALESCE(v.rule_count,0), COALESCE(v.pattern_count,0), "
           "(SELECT COUNT(*) FROM compiled_artifacts a WHERE a.version_id = v.version_id), "
           "(SELECT COUNT(*) FROM active_ruleset r WHERE r.version_id = v.version_id AND r.channel = 'default') "
           "FROM ruleset_versions v ORDER BY v.version_id");
    while (s.step()) {
        VersionRow r;
        r.version = s.text(0);
        r.status = s.text(1);
        r.content_digest = s.text(2);
        r.published_at = s.text(3);
        r.rule_count = static_cast<int>(s.int64(4));
        r.pattern_count = static_cast<int>(s.int64(5));
        r.artifacts = static_cast<int>(s.int64(6));
        r.active = s.int64(7) > 0;
        out.push_back(r);
    }
    return out;
}

std::vector<std::string> SqliteStore::provenance_of_pattern(uint32_t pattern_id) {
    std::vector<std::string> out;
    Stmt s(db_,
           "SELECT DISTINCT sr.source_id, sr.source_key, sr.source_path FROM rule_provenance p "
           "JOIN source_rules sr ON sr.source_rule_id = p.source_rule_id WHERE p.pattern_id = ? AND p.kind = 'pattern'");
    s.bind_int(1, static_cast<long long>(pattern_id));
    while (s.step()) out.push_back(s.text(0) + ":" + s.text(1) + " (" + s.text(2) + ")");
    return out;
}

}  // namespace apg
