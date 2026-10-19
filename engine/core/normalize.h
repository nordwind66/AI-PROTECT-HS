// Text normalisation views (versioned). The algorithms are specified by tools/apg_rules/normalize_ref.py and
// verified against tests/fixtures/normalize_golden.jsonl by the C++ unit tests.
//
//   raw       the input as it is
//   fold_v1   invisible/format/bidi/control characters removed, every character compatibility-folded
//             (NFKC of the single code point), Cyrillic/Greek look-alikes mapped to Latin
//   trans_v1  the preprocessing of the translation detector (strip, zero-width removal, homoglyphs, whitespace
//             collapse, control removal, CJK punctuation -> ASCII), without lower-casing
//   deobf_v1  fold_v1, then three anti-obfuscation passes: separators between CJK characters removed
//             ("忽 略 之 前" -> "忽略之前"), single letters spelled out with separators joined ("i.g.n.o.r.e" ->
//             "ignore"), leetspeak inside words decoded ("pr3v1ous" -> "previous")
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace apg {

enum class ViewKind : int { Raw = 0, FoldV1 = 1, TransV1 = 2, DeobfV1 = 3 };
constexpr int kViewKindCount = 4;

const char* view_name(ViewKind k);
bool view_from_name(const std::string& name, ViewKind* out);

struct Normalized {
    std::string text;
    // When requested: offsets[i] is the byte offset in the ORIGINAL text of the character that produced output
    // byte i; offsets.size() == text.size() + 1 and the last entry is the original length.
    std::vector<uint32_t> offsets;
};

// `input` must be valid UTF-8. Returns true when `out` holds a normalised text that DIFFERS from the input;
// returns false (and leaves `out` empty) when the view is identical to the input, so callers can reuse the
// input buffer instead of copying it.
bool normalize(ViewKind kind, const uint8_t* input, size_t n, bool want_offsets, Normalized& out);

}  // namespace apg
