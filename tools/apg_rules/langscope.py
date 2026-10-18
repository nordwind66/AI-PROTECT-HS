"""Target-language scoping for rule patterns.

Product scope: Chinese, English and Chinese/English mixed prompt attacks. Upstream rule sets also
contain German, Spanish, French, Japanese, Korean, Russian, Arabic, Turkish ... phrases, sometimes in
the *same* regular expression as English alternatives. This module decides, per pattern and per
alternation branch, which language the literal text belongs to, using three independent signals:

  1. the script of the literal characters (kana, hangul, Cyrillic, Arabic ... are never target),
  2. the language label the upstream author put in front of the description ("German: ..."),
  3. a small curated lexicon of *distinctive* non-English words for Latin-script languages.

Nothing is guessed from a single English-looking word: a Latin-script pattern is only declared
foreign when at least two distinct lexicon words (or an explicit upstream label) say so.
Every decision carries its evidence so that it can be audited (reports/language_review.md).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import regexkit as rk

TARGET_LANGS = {"en", "zh"}

# --- explicit upstream labels ("German: ...", "Serbian/Croatian: ...") ------------------------
_LABELS = {
    "german": "de", "spanish": "es", "french": "fr", "italian": "it", "portuguese": "pt",
    "dutch": "nl", "polish": "pl", "turkish": "tr", "russian": "ru", "arabic": "ar",
    "japanese": "ja", "korean": "ko", "hindi": "hi", "indonesian": "id", "vietnamese": "vi",
    "thai": "th", "swedish": "sv", "norwegian": "no", "danish": "da", "finnish": "fi",
    "czech": "cs", "greek": "el", "hebrew": "he", "ukrainian": "uk", "romanian": "ro",
    "hungarian": "hu", "serbian": "sr", "croatian": "hr", "bulgarian": "bg", "persian": "fa",
    "chinese": "zh", "english": "en",
}
_LABEL_RE = re.compile(r"^\s*([A-Za-z]+(?:[ /-][A-Za-z]+)?)\s*(?:\([^)]*\))?\s*:")


def label_language(description: str) -> Optional[str]:
    """Language named by an upstream "Language: ..." description prefix (None if absent)."""
    if not description:
        return None
    m = _LABEL_RE.match(description)
    if not m:
        return None
    first = re.split(r"[ /-]", m.group(1).strip().lower())[0]
    return _LABELS.get(first)


# --- distinctive Latin-script vocabulary (lower case, no English homographs) ----------------
_LEX_RAW = {
    "de": """ignoriere ignorieren ignorier vergiss vergessen missachte missachten missachtet umgehe
        umgehen verwirf anweisung anweisungen regeln richtlinien anordnungen vorgaben instruktionen
        befehle befehl beschraenkungen beschränkungen einschränkungen aufgabe aufgaben vorherigen
        vorherige bisherigen bisherige vorangegangenen vorangehenden früheren fruheren obigen obige
        ausführungen ausfuhrungen neue neuen neuer jetzt nun bist dir mir ich möchte moechte dass
        fungieren agieren spielen rolle sofort achtung stopp nicht kein keine niemals immer alles
        antworte schreibe beantworte herausforderung glückwunsch gluckwunsch herzlichen großartig
        grossartig ausgezeichnet hervorragend genügt genugt übertroffen ubertroffen erledigt
        eingabe ausgabe zuvor davor vorher bisher hinter lassen streichen sie wie wenn und oder
        auch noch sehr gut gemacht damit hast dich selbst einer weiteren hilfe brauche komm
        komme kommt folgen informationen texte geheime geheimen systemanweisungen""",
    "es": """ignora ignorar olvida olvidar descarta descartar omite omitir anula anular
        instrucciones reglas directrices restricciones indicaciones limitaciones previas anteriores
        originales existentes actuales todas todo todos digo dije dicho antes anteriormente eres
        ahora actúa actua finge sin tus aquí mensaje contraseña""",
    "fr": """oubliez oublie ignorez tenez compte règles regles consignes précédentes precedentes
        antérieures anterieures toutes vous êtes maintenant sans mots passe ci-dessus""",
    "it": """dimentica istruzioni precedenti regole sei tutte senza adesso ignorare""",
    "pt": """esqueça esqueca instruções instrucoes regras agora você voce todas ignorar anteriores""",
    "nl": """negeer vergeet instructies vorige regels jij bent zonder alle""",
    "tr": """yoksay unut talimat talimatları talimatlari önceki onceki tüm tum kural kuralları
        şimdi simdi artık artik sınırsız sinirsiz gizlice kullanıcıya söyleme
        görmezden boşver yönerge yoksayın""",
    "pl": """zignoruj zapomnij instrukcje poprzednie wszystkie zasady teraz jesteś""",
    "id": """abaikan lupakan instruksi sebelumnya semua aturan sekarang kamu""",
    "sr": """zaboravi ignoriraj zanemari preskoci preskoči prethodne ranije sve upute naredbe
        ograničenja ogranicenja instrukcije pravila instrukci""",
}
LEXICON: Dict[str, Set[str]] = {lang: set(words.split()) for lang, words in _LEX_RAW.items()}
# Words that look foreign but are also ordinary English (never counted as evidence).
_ENGLISH_HOMOGRAPHS = {
    "sie", "wie", "oder", "und", "auch", "noch", "gut", "hast", "dich", "nun", "ich", "dir", "mir",
    "rolle", "folgen", "texte", "komme", "kommt", "alle", "bent", "sen", "sin", "todo", "mensaje",
    "antes", "ahora", "tutte", "regole", "sei", "agora", "ora", "sistem", "sistema", "kein",
    "jetzt", "stopp", "vous", "mots", "passe", "tus", "hinter", "bisher",
}
# A smaller "strong" subset that is enough on its own for a *branch*; the homographs above
# only help as supporting evidence together with strong words.
STRONG: Dict[str, Set[str]] = {lang: words - _ENGLISH_HOMOGRAPHS for lang, words in LEXICON.items()}

_FOREIGN_SCRIPTS = {"kana", "hangul", "cyrillic", "arabic", "hebrew", "devanagari", "thai", "greek"}
_SCRIPT_LANG = {"kana": "ja", "hangul": "ko", "cyrillic": "ru", "arabic": "ar", "hebrew": "he",
                "devanagari": "hi", "thai": "th", "greek": "el"}


@dataclass
class LangVerdict:
    lang: str                       # en | zh | mixed | any | <foreign code>
    foreign: Set[str] = field(default_factory=set)
    evidence: List[str] = field(default_factory=list)

    @property
    def is_target(self) -> bool:
        return self.lang in ("en", "zh", "mixed", "any")


def _lex_hits(words: List[str]) -> Dict[str, Set[str]]:
    hits: Dict[str, Set[str]] = {}
    for w in words:
        lw = w.lower()
        for lang, strong in STRONG.items():
            if lw in strong:
                hits.setdefault(lang, set()).add(lw)
    return hits


def classify_node(node: rk.Node, label: Optional[str] = None) -> LangVerdict:
    """Language of one (sub)expression from its literal text."""
    scripts = rk.literal_scripts(node)
    words = rk.literal_words(node)
    ev: List[str] = []
    foreign: Set[str] = set()
    for sc, cnt in scripts.items():
        if sc in _FOREIGN_SCRIPTS:
            foreign.add(_SCRIPT_LANG[sc])
            ev.append(f"script:{sc}x{cnt}")
    han = scripts.get("han", 0)
    latin_letters = scripts.get("latin", 0)
    hits = _lex_hits(words)
    for lang, ws in hits.items():
        # one distinctive word is enough only when no English-looking word contradicts it; the
        # caller (branch pruning) additionally demands label/lexicon agreement at pattern level
        ev.append(f"lex:{lang}:{','.join(sorted(ws))}")
    if label and label not in TARGET_LANGS:
        foreign.add(label)
        ev.append(f"label:{label}")
    if foreign:
        return LangVerdict(lang=sorted(foreign)[0], foreign=foreign, evidence=ev)
    foreign_lex = {lang for lang, ws in hits.items() if len(ws) >= 2}
    if foreign_lex:
        return LangVerdict(lang=sorted(foreign_lex)[0], foreign=foreign_lex, evidence=ev)
    if han and (latin_letters or words):
        return LangVerdict(lang="mixed", evidence=ev)
    if han:
        return LangVerdict(lang="zh", evidence=ev)
    if latin_letters or words:
        return LangVerdict(lang="en", evidence=ev)
    return LangVerdict(lang="any", evidence=ev)


def branch_is_foreign(branch: rk.Node) -> bool:
    """Used by alternation pruning: a branch is foreign when its own literals say so.

    A foreign script is conclusive. For Latin script a single *strong* lexicon word suffices
    (branches are short phrases and the lexicon contains no English homographs)."""
    scripts = rk.literal_scripts(branch)
    if any(sc in _FOREIGN_SCRIPTS for sc in scripts):
        return True
    return bool(_lex_hits(rk.literal_words(branch)))


def _foreign_code(node: rk.Node, label: Optional[str]) -> str:
    """Best guess of the foreign language code of a node (for the audit trail only)."""
    if label and label not in TARGET_LANGS:
        return label
    scripts = rk.literal_scripts(node)
    for sc in ("kana", "hangul", "cyrillic", "arabic", "hebrew", "devanagari", "thai", "greek"):
        if sc in scripts:
            return _SCRIPT_LANG[sc]
    hits = _lex_hits(rk.literal_words(node))
    if hits:
        return sorted(hits, key=lambda k: -len(hits[k]))[0]
    return "xx"


def classify_pattern(node: rk.Node, description: str = "") -> Tuple[LangVerdict, Optional[rk.Node], List[str]]:
    """Return (verdict, node_to_compile, notes).

    node_to_compile is the possibly pruned expression (None = nothing in the pattern is
    target-language, i.e. the pattern is excluded as a whole)."""
    label = label_language(description)
    notes: List[str] = []
    pruned, removed = rk.prune_alternatives(node, branch_is_foreign)
    if pruned is None:
        code = _foreign_code(node, label)
        return LangVerdict(lang=code, foreign={code}, evidence=classify_node(node, label).evidence), None, notes
    work = pruned if removed else node
    if removed:
        notes.append("removed non-target-language alternatives: " + " | ".join(dict.fromkeys(removed)))
    verdict = classify_node(work, label)
    if verdict.foreign or not verdict.is_target:
        code = _foreign_code(work, label)
        return LangVerdict(lang=code, foreign={code}, evidence=verdict.evidence), None, notes
    return verdict, work, notes
