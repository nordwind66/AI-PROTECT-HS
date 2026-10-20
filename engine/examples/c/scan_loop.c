/*
 * examples/c/scan_loop.c -- interactive C client: reads one line from the terminal at a time, scans it with
 * libai_prompt_guard.so and prints the decision, the rules that hit and the evidence (the text that hit).
 *
 *   build (next to the package directory: lib/ include/ rules/):
 *     cc -O2 scan_loop.c -o scan_loop -I include -L lib -lai_prompt_guard -Wl,-rpath,'$ORIGIN/lib'
 *   run:
 *     ./scan_loop rules/active.json            summary per line
 *     ./scan_loop rules/active.json --json     the raw JSON result per line
 *   Type a line and press Enter; "quit", "exit" or Ctrl-D ends the program. Lines are scanned as UTF-8 user input.
 *
 * Contract demonstrated here (see docs/c-api.md):
 *   * one context for the whole process (apg_create once, apg_destroy at the end);
 *   * the result buffer belongs to the library -> release it with apg_free_buffer(), never free();
 *   * on a non-OK status the out parameters are NULL / 0 and apg_last_error() explains why;
 *   * a text that cannot be scanned (too long, not UTF-8) still gives status APG_OK with "status":"error" in the JSON.
 *
 * The summary below picks fields out of the JSON with plain string search to stay dependency free. That is fine for a demo;
 * a real program should parse the result with a JSON library (the format is schemas/response.schema.json).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_prompt_guard.h"

#define MAX_LINE 65535   /* bytes of one input line; the library's own default limit is limits.max_text_bytes = 1 MiB */
#define MAX_RULES_SHOWN 5

/* ---- tiny helpers to read values out of the result JSON ---------------------------------------------- */

/* Copies the string value of "key":"..." found in [from, to) into dst (JSON escapes \" \\ \n \t resolved). Returns 1 if found. */
static int json_string(const char* from, const char* to, const char* key, char* dst, size_t cap) {
    char pat[64];
    const char* p;
    size_t n = 0;
    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    p = strstr(from, pat);
    if (!p || p >= to) return 0;
    for (p += strlen(pat); *p && p < to && *p != '"' && n + 1 < cap; ++p) {
        if (*p == '\\' && p[1]) {
            ++p;
            dst[n++] = (*p == 'n') ? '\n' : (*p == 't') ? '\t' : *p;
        } else {
            dst[n++] = *p;
        }
    }
    dst[n] = '\0';
    return 1;
}

/* Reads the number after "key": (0 if absent). */
static double json_number(const char* json, const char* key) {
    char pat[64];
    const char* p;
    snprintf(pat, sizeof pat, "\"%s\":", key);
    p = strstr(json, pat);
    return p ? atof(p + strlen(pat)) : 0.0;
}

static void print_summary(const char* json) {
    char decision[32] = "?", level[32] = "?", version[64] = "?", backend[32] = "?", status[16] = "?", code[64] = "";
    char buf[1024], buf2[1024];
    const char* end = json + strlen(json);
    const char* rules = strstr(json, "\"matched_rules\":[");
    const char* stop = rules ? strstr(rules, "\"needs_context\":") : NULL;
    const char* p;
    int shown = 0, total = 0;

    json_string(json, end, "status", status, sizeof status);
    json_string(json, end, "decision", decision, sizeof decision);
    json_string(json, end, "risk_level", level, sizeof level);
    json_string(json, end, "ruleset_version", version, sizeof version);
    json_string(json, end, "backend", backend, sizeof backend);
    printf("决策: %s   风险分: %.4f (%s)   规则集: %s   后端: %s\n", decision, json_number(json, "score"), level, version, backend);
    if (strcmp(status, "ok") != 0) {
        json_string(json, end, "error_code", code, sizeof code);
        printf("  文本没有被扫描: %s (按策略给出决策 %s)\n", code, decision);
        return;
    }
    if (!rules || !stop) return;

    /* every rule object starts with "rule_id":"..." inside matched_rules */
    for (p = strstr(rules, "\"rule_id\":\""); p && p < stop; ++total) {
        const char* next = strstr(p + 1, "\"rule_id\":\"");
        const char* seg_end = (next && next < stop) ? next : stop;
        if (shown < MAX_RULES_SHOWN) {
            char id[64] = "", name[256] = "", cat[64] = "", sev[32] = "";
            json_string(p, seg_end, "rule_id", id, sizeof id);
            json_string(p, seg_end, "name", name, sizeof name);
            json_string(p, seg_end, "category", cat, sizeof cat);
            json_string(p, seg_end, "severity", sev, sizeof sev);
            printf("  命中规则 %d: %s  %s  [%s / %s]\n", shown + 1, id, name, cat, sev);
            if (json_string(p, seg_end, "matched_text", buf, sizeof buf)) {
                /* matched_text / normalized_text / sentence belong to ONE evidence object: stop at the next one */
                const char* ev = strstr(p, "\"matched_text\":\"");
                const char* ev_end = strstr(ev + 1, "{\"pattern_id\"");
                if (!ev_end || ev_end > seg_end) ev_end = seg_end;
                printf("    命中文本: %s\n", buf);
                if (json_string(ev, ev_end, "normalized_text", buf2, sizeof buf2)) printf("    归一化后: %s\n", buf2);
                if (json_string(ev, ev_end, "sentence", buf, sizeof buf)) printf("    所在句子: %s\n", buf);
            }
            ++shown;
        }
        p = (next && next < stop) ? next : NULL;
    }
    if (total > shown) printf("  ... 另有 %d 条命中规则 (用 --json 查看全部)\n", total - shown);
    if (total == 0) printf("  没有命中任何规则\n");
}

/* Appends s as a JSON string literal to dst (config building); returns 0 on overflow. */
static int append_json_string(char* dst, size_t cap, const char* s) {
    size_t n = strlen(dst);
    if (n + 2 >= cap) return 0;
    dst[n++] = '"';
    for (; *s; ++s) {
        if (*s == '"' || *s == '\\') {
            if (n + 3 >= cap) return 0;
            dst[n++] = '\\';
            dst[n++] = *s;
        } else {
            if (n + 2 >= cap) return 0;
            dst[n++] = *s;
        }
    }
    if (n + 2 >= cap) return 0;
    dst[n++] = '"';
    dst[n] = '\0';
    return 1;
}

int main(int argc, char** argv) {
    const char* manifest = (argc > 1 && strcmp(argv[1], "--json") != 0) ? argv[1] : "rules/active.json";
    int raw_json = 0, i;
    static char line[MAX_LINE + 1];
    char config[4096] = "{\"manifest_path\":";
    apg_context_t* ctx = NULL;
    apg_status_t st;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--json") == 0) raw_json = 1;
    }
    if (!append_json_string(config, sizeof config, manifest) || strlen(config) + 2 >= sizeof config) {
        fprintf(stderr, "manifest path too long\n");
        return 2;
    }
    strcat(config, "}");

    if ((apg_abi_version() >> 16) != APG_ABI_VERSION_MAJOR) {
        fprintf(stderr, "incompatible library ABI 0x%x\n", (unsigned)apg_abi_version());
        return 2;
    }
    st = apg_create((const uint8_t*)config, strlen(config), &ctx);
    if (st != APG_OK) {
        fprintf(stderr, "apg_create failed: %s: %s\n", apg_status_string(st), apg_last_error());
        return 1;
    }
    printf("AI Prompt Guard %s, 规则: %s\n输入一行文本后回车进行检测, quit / exit / Ctrl-D 退出\n", apg_engine_version(), manifest);

    while (1) {
        uint8_t* result = NULL;
        size_t result_len = 0;
        int n, ch;

        printf("\n> ");
        fflush(stdout);
        n = scanf("%65535[^\n]", line);      /* a whole line, spaces included; scanf("%s") would stop at the first space */
        if (n == EOF) break;                  /* Ctrl-D */
        /* consume the rest of the line (the newline, or whatever did not fit into the buffer) */
        while ((ch = getchar()) != '\n' && ch != EOF) {
        }
        if (n == 0) {                         /* empty line */
            if (ch == EOF) break;
            continue;
        }
        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) break;

        st = apg_scan_text(ctx, (const uint8_t*)line, strlen(line), "user_input", &result, &result_len);
        if (st != APG_OK) {
            fprintf(stderr, "apg_scan_text failed: %s: %s\n", apg_status_string(st), apg_last_error());
            continue;
        }
        if (raw_json) {
            fwrite(result, 1, result_len, stdout);
            putchar('\n');
        } else {
            /* the library's buffer is not NUL terminated by contract: copy before using string functions */
            char* json = (char*)malloc(result_len + 1);
            if (json) {
                memcpy(json, result, result_len);
                json[result_len] = '\0';
                print_summary(json);
                free(json);
            }
        }
        apg_free_buffer(result);
        if (ch == EOF) break;
    }

    apg_destroy(ctx);
    printf("bye\n");
    return 0;
}
