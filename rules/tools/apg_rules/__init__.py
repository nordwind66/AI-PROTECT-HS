"""apg_rules -- build-time rule management for AI Prompt Guard.

The runtime (C++ engine / C ABI) has NO Python dependency. This package is only used to
  * lock and extract the upstream rule repositories,
  * import / normalise / de-duplicate rules into the authoritative SQLite database,
  * maintain (list/show/add/update/enable/disable) rules,
  * validate, stage, publish and roll back immutable rule-set versions.

Only the Python standard library is used (no PyYAML, no third-party packages).
"""

TOOL_NAME = "apg-rules"
TOOL_VERSION = "1.0.0"

# Version of the importer/normaliser logic. Bump when the extraction semantics change so that
# re-imports of an unchanged upstream commit are detected as "tool changed" in `diff`.
EXTRACTOR_API_VERSION = 1

# Snapshot document format (schemas/ruleset_snapshot.schema.json)
SNAPSHOT_FORMAT_VERSION = 1
