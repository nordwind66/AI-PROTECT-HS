/*
 * ai_prompt_guard.h -- the ONE public, stable C ABI of the AI Prompt Guard engine.
 *
 * The same header is used for
 *   - Windows x86-64 : ai_prompt_guard.dll + ai_prompt_guard.lib (import library)
 *   - Linux   x86-64 : libai_prompt_guard.so  (and optionally libai_prompt_guard.a)
 *
 * Design rules (see docs/c-api.md for the long form):
 *   * Pure C interface. No C++ types, exceptions, STL containers or struct layouts cross
 *     the boundary. Every exported function catches all C++ exceptions internally.
 *   * Strings that go in are UTF-8 with an explicit byte length (or NUL-terminated for the few
 *     "const char *" parameters). Strings that come out are UTF-8 JSON documents allocated by the
 *     library. They MUST be released with apg_free_buffer() -- never with free()/delete, because on
 *     Windows the caller and the DLL may use different C runtimes.
 *   * On any non-APG_OK return value *out_json is set to NULL and *out_len to 0, and a
 *     human-readable diagnostic is available through apg_last_error() on the calling thread.
 *   * One apg_context_t may be shared by any number of threads. apg_scan_text, apg_scan_json,
 *     apg_get_info and apg_reload are thread-safe with respect to each other.
 *   * apg_destroy() blocks until scans/reloads that STARTED before it was called have finished.
 *     The caller must guarantee that no thread starts a new call on the context after (or
 *     concurrently with) apg_destroy(); that is a use-after-free of the handle, which no
 *     C API can defend against.
 *
 * Compatibility policy:
 *   * apg_abi_version() returns (major << 16) | (minor << 8) | patch of the ABI the *library* was
 *     built with. A change of the MAJOR number means a binary-incompatible change. A client
 *     compiled against this header must check
 *         (apg_abi_version() >> 16) == APG_ABI_VERSION_MAJOR
 *     and that the minor version of the library is >= APG_ABI_VERSION_MINOR.
 *   * The JSON documents have their own "schema_version" field which is versioned independently
 *     of the ABI (see schemas/*.schema.json).
 *   * New functions may be appended in a minor version. Existing signatures never change inside
 *     a major version.
 */
#ifndef AI_PROMPT_GUARD_H
#define AI_PROMPT_GUARD_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------------------------------
 * Export / calling-convention macros
 *   APG_BUILD_DLL : defined while building the shared library itself (CMake does this)
 *   APG_STATIC    : define when linking the static library on Windows (no dllimport)
 * ---------------------------------------------------------------------------------------- */
#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(APG_STATIC)
#    define APG_API
#  elif defined(APG_BUILD_DLL)
#    define APG_API __declspec(dllexport)
#  else
#    define APG_API __declspec(dllimport)
#  endif
#  define APG_CALL __cdecl
#else
#  if defined(__GNUC__) || defined(__clang__)
#    define APG_API __attribute__((visibility("default")))
#  else
#    define APG_API
#  endif
#  define APG_CALL
#endif

#define APG_ABI_VERSION_MAJOR 1u
#define APG_ABI_VERSION_MINOR 0u
#define APG_ABI_VERSION_PATCH 0u
#define APG_ABI_VERSION \
    ((APG_ABI_VERSION_MAJOR << 16) | (APG_ABI_VERSION_MINOR << 8) | APG_ABI_VERSION_PATCH)

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque engine handle. */
typedef struct apg_context apg_context_t;

/* Return codes of every function that returns a status. */
typedef enum apg_status {
    APG_OK                    = 0, /* success                                                       */
    APG_ERR_INVALID_ARGUMENT  = 1, /* NULL pointer, malformed request JSON, bad field type, ...      */
    APG_ERR_CONFIG            = 2, /* configuration JSON invalid / manifest path missing             */
    APG_ERR_DATABASE          = 3, /* compiled rule database, manifest or metadata unreadable,
                                      corrupt, hash mismatch or internally inconsistent             */
    APG_ERR_VERSION           = 4, /* artifact built by an incompatible Hyperscan / ABI / schema    */
    APG_ERR_PLATFORM          = 5, /* artifact built for another OS / CPU / backend                 */
    APG_ERR_OOM               = 6, /* memory allocation failed                                      */
    APG_ERR_LIMIT             = 7, /* a hard resource limit was exceeded before scanning started
                                      (e.g. request JSON larger than limits.max_request_bytes)       */
    APG_ERR_INTERNAL          = 8  /* bug / unexpected exception (details in apg_last_error())       */
} apg_status_t;

/* ---- identification --------------------------------------------------------------------- */

/* ABI version of the loaded library, see APG_ABI_VERSION. */
APG_API uint32_t APG_CALL apg_abi_version(void);

/* Engine (implementation) version string, e.g. "1.0.0". Static storage; do not free. */
APG_API const char *APG_CALL apg_engine_version(void);

/* Short constant name for a status code ("APG_OK", ...). Static storage; do not free. */
APG_API const char *APG_CALL apg_status_string(apg_status_t status);

/* Diagnostic text of the last failing apg_* call made on the CALLING THREAD (UTF-8, never NULL;
 * empty string if the last call succeeded). Valid until the next apg_* call on this thread. */
APG_API const char *APG_CALL apg_last_error(void);

/* ---- lifecycle --------------------------------------------------------------------------- */

/*
 * Create an engine instance.
 *   config_json / config_len : UTF-8 JSON, see schemas/config.schema.json. Must contain
 *                              "manifest_path" (UTF-8 path of dist/<os>/<arch>/<ver>/manifest.json).
 *                              Unknown keys are rejected (APG_ERR_CONFIG) so typos do not
 *                              silently disable limits.
 *   out_ctx                  : receives the handle; *out_ctx is NULL on failure.
 * The function loads the manifest, verifies the SHA-256 of every referenced file, checks the
 * platform / Hyperscan version, deserialises the pattern databases, allocates scratch space
 * and builds the immutable in-memory rule snapshot. It never opens SQLite and never compiles
 * a regular expression from source on the request path.
 */
APG_API apg_status_t APG_CALL apg_create(const uint8_t *config_json, size_t config_len,
                                         apg_context_t **out_ctx);

/*
 * Atomically switch to a new rule set. The new manifest is completely loaded and verified
 * (including scratch creation) before the switch; in-flight scans keep using the old snapshot,
 * new scans use the new one. On failure the running rule set is untouched and an error code
 * is returned.
 */
APG_API apg_status_t APG_CALL apg_reload(apg_context_t *ctx, const char *manifest_path_utf8);

/* Destroy the handle (NULL is allowed). See the concurrency contract in the file header. */
APG_API void APG_CALL apg_destroy(apg_context_t *ctx);

/* ---- scanning ---------------------------------------------------------------------------- */

/*
 * High-frequency entry point.
 *   utf8 / utf8_len : the text; explicit byte length, embedded NUL bytes (U+0000) are allowed and
 *                     treated as ordinary (ignorable) characters. utf8 may be NULL only if
 *                     utf8_len == 0.
 *   source          : NUL-terminated UTF-8 label of the text origin: "user_input", "tool_output",
 *                     "rag_document" or "agent_message". NULL means "user_input".
 *   out_json        : receives a library-allocated UTF-8 JSON result document (schema_version 1,
 *                     schemas/response.schema.json). Free with apg_free_buffer().
 *   out_len         : length of the document in bytes (without terminator; the buffer is
 *                     additionally NUL-terminated for convenience).
 * Problems with the text itself (invalid UTF-8, text larger than limits.max_text_bytes,
 * scan budget exhausted) are reported INSIDE the JSON ("status" != "ok", "error_code") together
 * with a decision derived from the configured failure policy, and the function returns APG_OK.
 */
APG_API apg_status_t APG_CALL apg_scan_text(apg_context_t *ctx, const uint8_t *utf8,
                                            size_t utf8_len, const char *source,
                                            uint8_t **out_json, size_t *out_len);

/*
 * Structured entry point: request_json is a UTF-8 JSON document (schemas/request.schema.json) with
 * text / fields / source / role / request_id / context. Both entry points share the same
 * detection and decision logic.
 */
APG_API apg_status_t APG_CALL apg_scan_json(apg_context_t *ctx, const uint8_t *request_json,
                                            size_t request_len, uint8_t **out_json,
                                            size_t *out_len);

/*
 * Describe the currently active rule set as a JSON document: engine / ABI version, ruleset
 * version, ruleset hash, backend, Hyperscan version, number of rules / patterns, load time.
 */
APG_API apg_status_t APG_CALL apg_get_info(apg_context_t *ctx, uint8_t **out_json,
                                           size_t *out_len);

/* ---- memory ------------------------------------------------------------------------------ */

/* Release a buffer returned by apg_scan_text / apg_scan_json / apg_get_info (NULL is allowed). */
APG_API void APG_CALL apg_free_buffer(void *ptr);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AI_PROMPT_GUARD_H */
