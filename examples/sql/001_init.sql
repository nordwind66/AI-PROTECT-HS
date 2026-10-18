-- =====================================================================================
-- AI Prompt Guard rule database -- migration 001 (schema version 1)
--
-- SQLite is the ONE authoritative store of rules. Everything else (snapshot JSON, .hsdb,
-- manifest, CSV reports) is generated from it.
--
-- Portability: only features available in SQLite >= 3.24 are used (no STRICT tables, no
-- RETURNING, no JSON functions inside constraints) so the file can be read by the SQLite
-- shipped with Ubuntu 20.04 / RHEL 8 as well as by Windows builds.
-- Always run with:  PRAGMA foreign_keys = ON;   (the tools and the C++ CLI do this)
-- Timestamps are UTC ISO-8601 text, e.g. 2026-10-16T07:12:34Z.
-- =====================================================================================

-- ---- bookkeeping -----------------------------------------------------------------------
CREATE TABLE schema_migrations (
    version       INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    checksum      TEXT NOT NULL,                 -- sha256 of the migration file bytes
    applied_at    TEXT NOT NULL,
    tool_version  TEXT
);

-- Monotonic allocators. Values are never reused: not for pattern ids, not for rule numbers.
CREATE TABLE id_counters (
    name        TEXT PRIMARY KEY,
    next_value  INTEGER NOT NULL CHECK (next_value > 0)
);
INSERT INTO id_counters (name, next_value) VALUES ('pattern_id', 10001);
INSERT INTO id_counters (name, next_value) VALUES ('ruleset_version_id', 1);

-- ---- upstream provenance ---------------------------------------------------------------
CREATE TABLE upstream_sources (
    source_id          TEXT PRIMARY KEY,         -- atr | trans_pid | fevzi_pidr | <future>
    display_name       TEXT NOT NULL,
    repo_url           TEXT NOT NULL,
    branch             TEXT,
    commit_sha         TEXT NOT NULL,            -- commit currently reflected in source_rules
    commit_date        TEXT,
    commit_subject     TEXT,
    license_spdx       TEXT NOT NULL,
    lock_tree_sha256   TEXT,                     -- digest of the locked file set
    extractor_id       TEXT NOT NULL,
    extractor_version  TEXT NOT NULL,
    synced_at          TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('active', 'stale', 'error', 'disabled'))
);

CREATE TABLE import_jobs (
    job_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id     TEXT NOT NULL REFERENCES upstream_sources (source_id),
    commit_sha    TEXT NOT NULL,
    mode          TEXT NOT NULL CHECK (mode IN ('apply', 'dry-run')),
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT NOT NULL CHECK (status IN ('running', 'ok', 'failed', 'dry-run')),
    tool_version  TEXT NOT NULL,
    summary_json  TEXT,                          -- counters (new / changed / unchanged / removed ...)
    error_text    TEXT
);

CREATE TABLE source_rules (
    source_rule_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id            TEXT NOT NULL REFERENCES upstream_sources (source_id),
    source_key           TEXT NOT NULL,          -- upstream rule id / detector group name
    name                 TEXT NOT NULL,
    source_path          TEXT NOT NULL,          -- file inside the upstream repository
    locator              TEXT,                   -- key path / line information
    group_key            TEXT,                   -- upstream business group (scoring group)
    lang_declared        TEXT,
    upstream_status      TEXT,
    upstream_severity    TEXT,
    upstream_maturity    TEXT,
    upstream_confidence  REAL,
    combinator           TEXT,                   -- any | all | boolean expression text
    raw_json             TEXT NOT NULL,          -- trimmed original definition (canonical JSON)
    content_hash         TEXT NOT NULL,          -- sha256 of raw_json + extractor semantics
    file_blob_sha        TEXT,                   -- git blob id of the defining file
    first_commit         TEXT NOT NULL,
    last_commit          TEXT NOT NULL,
    decision             TEXT NOT NULL CHECK (decision IN
                           ('included', 'partial', 'excluded_scope', 'excluded_language',
                            'unsupported', 'context_logic')),
    decision_reason      TEXT,
    state                TEXT NOT NULL CHECK (state IN ('active', 'removed_upstream')),
    imported_at          TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    UNIQUE (source_id, source_key)
);
CREATE INDEX idx_source_rules_decision ON source_rules (source_id, decision);

-- Earlier definitions of a source rule that changed between upstream commits.
CREATE TABLE source_rule_history (
    history_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    source_rule_id  INTEGER NOT NULL REFERENCES source_rules (source_rule_id),
    commit_sha      TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    raw_json        TEXT NOT NULL,
    replaced_at     TEXT NOT NULL
);

-- Every regular expression of every source rule with its final fate. Nothing disappears:
-- excluded / unsupported patterns stay here with the reason.
CREATE TABLE source_patterns (
    source_pattern_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_rule_id     INTEGER NOT NULL REFERENCES source_rules (source_rule_id) ON DELETE CASCADE,
    ordinal            INTEGER NOT NULL,
    locator            TEXT,
    line_no            INTEGER,
    field_name         TEXT,
    operator           TEXT,
    dialect            TEXT NOT NULL CHECK (dialect IN ('es', 'py', 'pcre')),
    regex_original     TEXT NOT NULL,
    flags_original     TEXT NOT NULL DEFAULT '',
    description        TEXT,
    lang_detected      TEXT,
    fate               TEXT NOT NULL CHECK (fate IN
                         ('hs_native', 'hs_prefilter_pcre2', 'context_logic',
                          'excluded_language', 'excluded_scope', 'unsupported')),
    fate_reason        TEXT,
    transform_notes    TEXT,                     -- JSON array: conversions / pruning performed
    UNIQUE (source_rule_id, ordinal)
);
CREATE INDEX idx_source_patterns_fate ON source_patterns (fate);

-- ---- unified rules -----------------------------------------------------------------------
CREATE TABLE rules (
    rule_id           TEXT PRIMARY KEY,          -- stable business id, e.g. AIPS-PI-0001
    name              TEXT NOT NULL,
    category          TEXT NOT NULL CHECK (category IN
                        ('prompt_injection', 'jailbreak', 'role_spoofing', 'instruction_override',
                         'instruction_hijacking', 'system_prompt_extraction', 'safety_bypass',
                         'obfuscated_injection', 'data_exfiltration_instruction')),
    lang              TEXT NOT NULL CHECK (lang IN ('zh', 'en', 'mixed', 'any')),
    severity          TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    weight            REAL NOT NULL CHECK (weight >= 0 AND weight <= 1),     -- risk contribution
    confidence        REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1), -- P(true attack | match)
    default_action    TEXT NOT NULL CHECK (default_action IN ('allow', 'alert', 'review', 'block')),
    status            TEXT NOT NULL CHECK (status IN ('enabled', 'disabled', 'deprecated', 'deleted')),
    origin            TEXT NOT NULL CHECK (origin IN ('imported', 'manual')),
    scope             TEXT NOT NULL DEFAULT 'general'
                        CHECK (scope IN ('general', 'translation_only', 'context_required')),
    context_requires  TEXT,                      -- JSON object that request.context must satisfy
    score_group       TEXT,                      -- hits of rules in one group do not stack
    description       TEXT,
    tags              TEXT,                      -- JSON array of strings
    revision          INTEGER NOT NULL DEFAULT 1,
    modified_locally  INTEGER NOT NULL DEFAULT 0 CHECK (modified_locally IN (0, 1)),
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    deleted_at        TEXT
);
CREATE INDEX idx_rules_category ON rules (category, status);
CREATE INDEX idx_rules_lang ON rules (lang, status);

-- Patterns are immutable and de-duplicated by expr_hash. pattern_id is the Hyperscan id.
CREATE TABLE rule_patterns (
    pattern_id    INTEGER PRIMARY KEY CHECK (pattern_id BETWEEN 1 AND 4294967295),
    regex         TEXT NOT NULL,                 -- canonical PCRE/Hyperscan-compatible expression
    flags         TEXT NOT NULL DEFAULT '',      -- subset of: i m s u
    norm_profile  TEXT NOT NULL,                 -- fold_v1 | trans_v1 | raw_v1
    lang          TEXT NOT NULL CHECK (lang IN ('zh', 'en', 'mixed', 'any')),
    engine_class  TEXT NOT NULL CHECK (engine_class IN
                    ('hs_native', 'hs_prefilter_pcre2', 'unsupported')),
    class_reason  TEXT,
    features      TEXT,                          -- JSON array of feature tags
    min_len       INTEGER,
    max_len       INTEGER,                       -- NULL = unbounded
    expr_hash     TEXT NOT NULL UNIQUE,          -- sha256(regex | flags | norm_profile)
    created_at    TEXT NOT NULL
);

-- Which pattern implements which condition leaf of which rule revision (many-to-many).
CREATE TABLE rule_pattern_links (
    rule_id     TEXT NOT NULL REFERENCES rules (rule_id),
    revision    INTEGER NOT NULL,
    leaf_key    TEXT NOT NULL,                   -- leaf name used inside rule_conditions.ast_json
    pattern_id  INTEGER NOT NULL REFERENCES rule_patterns (pattern_id),
    field_name  TEXT NOT NULL DEFAULT 'content',
    ordinal     INTEGER NOT NULL,
    PRIMARY KEY (rule_id, revision, leaf_key)
);
CREATE INDEX idx_links_pattern ON rule_pattern_links (pattern_id);

-- Versioned condition tree: {"op":"any|all|not","args":[...]} / {"op":"leaf","id":"c1"} ...
CREATE TABLE rule_conditions (
    rule_id    TEXT NOT NULL REFERENCES rules (rule_id),
    revision   INTEGER NOT NULL,
    ast_json   TEXT NOT NULL,
    PRIMARY KEY (rule_id, revision)
);

CREATE TABLE rule_provenance (
    prov_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind               TEXT NOT NULL CHECK (kind IN ('rule', 'pattern')),
    rule_id            TEXT REFERENCES rules (rule_id),
    pattern_id         INTEGER REFERENCES rule_patterns (pattern_id),
    source_rule_id     INTEGER NOT NULL REFERENCES source_rules (source_rule_id),
    source_pattern_id  INTEGER REFERENCES source_patterns (source_pattern_id),
    source_commit      TEXT NOT NULL,
    note               TEXT,
    CHECK (rule_id IS NOT NULL OR pattern_id IS NOT NULL)
);
CREATE INDEX idx_prov_rule ON rule_provenance (rule_id);
CREATE INDEX idx_prov_pattern ON rule_provenance (pattern_id);
CREATE INDEX idx_prov_source ON rule_provenance (source_rule_id);

CREATE TABLE rule_tests (
    test_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id         TEXT NOT NULL REFERENCES rules (rule_id),
    kind            TEXT NOT NULL CHECK (kind IN ('positive', 'negative', 'mixed', 'known_gap')),
    text            TEXT NOT NULL,               -- primary text (may be empty when only fields_json is used)
    fields_json     TEXT,                        -- extra named fields (tool_name, tool_args, ...) as a JSON object
    text_sha256     TEXT NOT NULL,               -- sha256(text + canonical fields_json): identity of the sample
    lang            TEXT,
    scan_source     TEXT NOT NULL DEFAULT 'user_input',
    expect_hit      INTEGER NOT NULL CHECK (expect_hit IN (0, 1)),
    expect_category TEXT,
    expect_action   TEXT,
    origin          TEXT NOT NULL CHECK (origin IN ('upstream', 'manual', 'generated')),
    source_rule_id  INTEGER REFERENCES source_rules (source_rule_id),
    test_version    INTEGER NOT NULL DEFAULT 1,
    verification    TEXT NOT NULL DEFAULT 'unverified' CHECK (verification IN
                      ('unverified', 'python_oracle_ok', 'python_oracle_mismatch', 'skipped_scope')),
    note            TEXT,
    created_at      TEXT NOT NULL,
    UNIQUE (rule_id, kind, text_sha256)
);
CREATE INDEX idx_rule_tests_rule ON rule_tests (rule_id);

CREATE TABLE rule_revisions (
    rule_id       TEXT NOT NULL REFERENCES rules (rule_id),
    revision      INTEGER NOT NULL,
    change_kind   TEXT NOT NULL CHECK (change_kind IN
                    ('create', 'import_update', 'edit', 'enable', 'disable', 'delete', 'restore')),
    content_json  TEXT NOT NULL,                 -- complete frozen rule (fields + condition + links)
    content_hash  TEXT NOT NULL,
    before_hash   TEXT,
    actor         TEXT NOT NULL,
    reason        TEXT,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (rule_id, revision)
);

-- ---- immutable rule-set versions ---------------------------------------------------------
CREATE TABLE ruleset_versions (
    version_id           INTEGER PRIMARY KEY,
    version              TEXT NOT NULL UNIQUE,   -- semantic version, e.g. 1.0.0
    status               TEXT NOT NULL CHECK (status IN ('draft', 'published', 'retired')),
    content_digest       TEXT,                   -- sha256 of the version-independent payload
    snapshot_sha256      TEXT,                   -- sha256 of the stored snapshot document
    rule_count           INTEGER,
    pattern_count        INTEGER,
    source_digest        TEXT,                   -- digest of the upstream lock state
    previous_version_id  INTEGER REFERENCES ruleset_versions (version_id),
    snapshot_format      INTEGER NOT NULL DEFAULT 1,
    created_at           TEXT NOT NULL,
    published_at         TEXT,
    retired_at           TEXT,
    created_by           TEXT,
    notes                TEXT
);

CREATE TABLE ruleset_members (
    version_id  INTEGER NOT NULL REFERENCES ruleset_versions (version_id),
    rule_id     TEXT NOT NULL REFERENCES rules (rule_id),
    revision    INTEGER NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    PRIMARY KEY (version_id, rule_id),
    FOREIGN KEY (rule_id, revision) REFERENCES rule_revisions (rule_id, revision)
);

CREATE TABLE ruleset_patterns (
    version_id  INTEGER NOT NULL REFERENCES ruleset_versions (version_id),
    pattern_id  INTEGER NOT NULL REFERENCES rule_patterns (pattern_id),
    PRIMARY KEY (version_id, pattern_id)
);

-- The exact bytes the compiler / engine consume. sha256(body) == ruleset_versions.snapshot_sha256.
CREATE TABLE ruleset_snapshots (
    version_id  INTEGER PRIMARY KEY REFERENCES ruleset_versions (version_id),
    body        BLOB NOT NULL,
    sha256      TEXT NOT NULL
);

-- Runtime pointer ("activate" / "rollback" move it; published versions never change).
CREATE TABLE active_ruleset (
    channel              TEXT PRIMARY KEY,
    version_id           INTEGER NOT NULL REFERENCES ruleset_versions (version_id),
    previous_version_id  INTEGER REFERENCES ruleset_versions (version_id),
    activated_at         TEXT NOT NULL,
    activated_by         TEXT,
    reason               TEXT
);

-- ---- build results --------------------------------------------------------------------
CREATE TABLE compiled_artifacts (
    artifact_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id       INTEGER NOT NULL REFERENCES ruleset_versions (version_id),
    target_os        TEXT NOT NULL,
    arch             TEXT NOT NULL,
    backend          TEXT NOT NULL CHECK (backend IN ('hyperscan', 'pcre2_fallback')),
    hs_version       TEXT,
    cpu_features     TEXT,
    cpu_target       TEXT,
    engine_abi       INTEGER,
    compiler_version TEXT,
    manifest_sha256  TEXT NOT NULL,
    hsdb_sha256      TEXT,
    meta_sha256      TEXT NOT NULL,
    rel_path         TEXT NOT NULL,              -- manifest path relative to the project root
    status           TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'failed')),
    pattern_total    INTEGER,
    pattern_native   INTEGER,
    pattern_prefilter INTEGER,
    pattern_failed   INTEGER,
    built_at         TEXT NOT NULL,
    report_json      TEXT
);
CREATE INDEX idx_artifacts_version ON compiled_artifacts (version_id);

CREATE TABLE compiled_pattern_results (
    artifact_id  INTEGER NOT NULL REFERENCES compiled_artifacts (artifact_id),
    pattern_id   INTEGER NOT NULL REFERENCES rule_patterns (pattern_id),
    final_class  TEXT NOT NULL CHECK (final_class IN ('hs_native', 'hs_prefilter_pcre2', 'unsupported')),
    error_text   TEXT,
    PRIMARY KEY (artifact_id, pattern_id)
);

-- ---- audit & issues --------------------------------------------------------------------
-- Hash-chained, append-only. Contains rule ids and counters, never prompt text from requests.
CREATE TABLE audit_log (
    audit_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    object_type  TEXT NOT NULL,
    object_id    TEXT,
    detail       TEXT,
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL
);

CREATE TABLE rule_issues (
    issue_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    kind           TEXT NOT NULL,
    severity       TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'error')),
    source_id      TEXT,
    source_key     TEXT,
    rule_id        TEXT,
    pattern_id     INTEGER,
    message        TEXT NOT NULL,
    detail         TEXT,
    status         TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'waived')),
    import_job_id  INTEGER REFERENCES import_jobs (job_id),
    created_at     TEXT NOT NULL,
    resolved_at    TEXT
);
CREATE INDEX idx_issues_kind ON rule_issues (kind, status);

-- =====================================================================================
-- Integrity triggers: immutability is enforced by the database, not by convention.
-- =====================================================================================
CREATE TRIGGER trg_rule_patterns_immutable
BEFORE UPDATE OF pattern_id, regex, flags, norm_profile, expr_hash ON rule_patterns
BEGIN
    SELECT RAISE(ABORT, 'rule_patterns are immutable: create a new pattern (new pattern_id) instead');
END;

CREATE TRIGGER trg_rule_patterns_no_delete
BEFORE DELETE ON rule_patterns
BEGIN
    SELECT RAISE(ABORT, 'pattern ids are never reused: rule_patterns rows cannot be deleted');
END;

CREATE TRIGGER trg_rule_revisions_no_update
BEFORE UPDATE ON rule_revisions
BEGIN
    SELECT RAISE(ABORT, 'rule_revisions is append-only');
END;

CREATE TRIGGER trg_rule_revisions_no_delete
BEFORE DELETE ON rule_revisions
BEGIN
    SELECT RAISE(ABORT, 'rule_revisions is append-only');
END;

CREATE TRIGGER trg_audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER trg_audit_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER trg_ruleset_versions_frozen
BEFORE UPDATE ON ruleset_versions
WHEN OLD.status IN ('published', 'retired')
 AND (NEW.version IS NOT OLD.version
   OR NEW.content_digest IS NOT OLD.content_digest
   OR NEW.snapshot_sha256 IS NOT OLD.snapshot_sha256
   OR NEW.rule_count IS NOT OLD.rule_count
   OR NEW.pattern_count IS NOT OLD.pattern_count
   OR NEW.source_digest IS NOT OLD.source_digest
   OR NEW.previous_version_id IS NOT OLD.previous_version_id
   OR NEW.snapshot_format IS NOT OLD.snapshot_format
   OR NEW.created_at IS NOT OLD.created_at
   OR NEW.published_at IS NOT OLD.published_at
   OR (OLD.status = 'retired' AND NEW.status <> 'retired')
   OR (OLD.status = 'published' AND NEW.status = 'draft'))
BEGIN
    SELECT RAISE(ABORT, 'a published rule-set version is immutable');
END;

CREATE TRIGGER trg_ruleset_versions_no_delete
BEFORE DELETE ON ruleset_versions
WHEN OLD.status IN ('published', 'retired')
BEGIN
    SELECT RAISE(ABORT, 'published rule-set versions cannot be deleted');
END;

CREATE TRIGGER trg_ruleset_members_frozen_ins
BEFORE INSERT ON ruleset_members
WHEN (SELECT status FROM ruleset_versions WHERE version_id = NEW.version_id) <> 'draft'
BEGIN
    SELECT RAISE(ABORT, 'ruleset_members of a non-draft version are immutable');
END;

CREATE TRIGGER trg_ruleset_members_frozen_upd
BEFORE UPDATE ON ruleset_members
WHEN (SELECT status FROM ruleset_versions WHERE version_id = OLD.version_id) <> 'draft'
BEGIN
    SELECT RAISE(ABORT, 'ruleset_members of a non-draft version are immutable');
END;

CREATE TRIGGER trg_ruleset_members_frozen_del
BEFORE DELETE ON ruleset_members
WHEN (SELECT status FROM ruleset_versions WHERE version_id = OLD.version_id) <> 'draft'
BEGIN
    SELECT RAISE(ABORT, 'ruleset_members of a non-draft version are immutable');
END;

CREATE TRIGGER trg_ruleset_patterns_frozen_ins
BEFORE INSERT ON ruleset_patterns
WHEN (SELECT status FROM ruleset_versions WHERE version_id = NEW.version_id) <> 'draft'
BEGIN
    SELECT RAISE(ABORT, 'ruleset_patterns of a non-draft version are immutable');
END;

CREATE TRIGGER trg_ruleset_patterns_frozen_del
BEFORE DELETE ON ruleset_patterns
WHEN (SELECT status FROM ruleset_versions WHERE version_id = OLD.version_id) <> 'draft'
BEGIN
    SELECT RAISE(ABORT, 'ruleset_patterns of a non-draft version are immutable');
END;

CREATE TRIGGER trg_ruleset_snapshots_frozen_ins
BEFORE INSERT ON ruleset_snapshots
WHEN (SELECT status FROM ruleset_versions WHERE version_id = NEW.version_id) <> 'draft'
BEGIN
    SELECT RAISE(ABORT, 'snapshot of a non-draft version is immutable');
END;

CREATE TRIGGER trg_ruleset_snapshots_frozen_upd
BEFORE UPDATE ON ruleset_snapshots
WHEN (SELECT status FROM ruleset_versions WHERE version_id = OLD.version_id) <> 'draft'
BEGIN
    SELECT RAISE(ABORT, 'snapshot of a non-draft version is immutable');
END;

CREATE TRIGGER trg_ruleset_snapshots_frozen_del
BEFORE DELETE ON ruleset_snapshots
WHEN (SELECT status FROM ruleset_versions WHERE version_id = OLD.version_id) <> 'draft'
BEGIN
    SELECT RAISE(ABORT, 'snapshot of a non-draft version is immutable');
END;

CREATE TRIGGER trg_artifacts_published_only
BEFORE INSERT ON compiled_artifacts
WHEN (SELECT status FROM ruleset_versions WHERE version_id = NEW.version_id) <> 'published'
BEGIN
    SELECT RAISE(ABORT, 'artifacts can only be registered for published rule-set versions');
END;

-- =====================================================================================
-- Convenience views (read-only helpers for sqlite3 users)
-- =====================================================================================
CREATE VIEW v_rule_overview AS
SELECT r.rule_id, r.name, r.category, r.lang, r.severity, r.weight, r.confidence,
       r.default_action, r.status, r.scope, r.score_group, r.revision, r.origin,
       (SELECT COUNT(*) FROM rule_pattern_links l
         WHERE l.rule_id = r.rule_id AND l.revision = r.revision)      AS pattern_links,
       (SELECT COUNT(*) FROM rule_tests t WHERE t.rule_id = r.rule_id AND t.expect_hit = 1) AS positive_tests,
       (SELECT COUNT(*) FROM rule_tests t WHERE t.rule_id = r.rule_id AND t.expect_hit = 0) AS negative_tests,
       (SELECT GROUP_CONCAT(DISTINCT s.source_id)
          FROM rule_provenance p JOIN source_rules s ON s.source_rule_id = p.source_rule_id
         WHERE p.rule_id = r.rule_id AND p.kind = 'rule')               AS sources
  FROM rules r;

CREATE VIEW v_rule_patterns_current AS
SELECT l.rule_id, l.leaf_key, l.field_name, p.pattern_id, p.engine_class, p.norm_profile,
       p.flags, p.lang AS pattern_lang, p.regex
  FROM rules r
  JOIN rule_pattern_links l ON l.rule_id = r.rule_id AND l.revision = r.revision
  JOIN rule_patterns p ON p.pattern_id = l.pattern_id;

CREATE VIEW v_source_rule_fates AS
SELECT s.source_id, s.source_key, s.name, s.decision, s.decision_reason, s.state,
       (SELECT COUNT(*) FROM source_patterns sp WHERE sp.source_rule_id = s.source_rule_id) AS patterns
  FROM source_rules s;

CREATE VIEW v_version_summary AS
SELECT v.version, v.status, v.rule_count, v.pattern_count, v.content_digest, v.published_at,
       (SELECT COUNT(*) FROM compiled_artifacts a WHERE a.version_id = v.version_id) AS artifacts,
       CASE WHEN a.version_id = v.version_id THEN 1 ELSE 0 END AS is_active
  FROM ruleset_versions v
  LEFT JOIN active_ruleset a ON a.channel = 'default';
