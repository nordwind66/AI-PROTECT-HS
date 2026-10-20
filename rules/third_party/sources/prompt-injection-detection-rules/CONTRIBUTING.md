# Contributing

New rules — especially non-English phrasings and fresh evasions — are the most
valuable contribution.

## Add a rule
1. Add a YAML document to the right `rules/<category>.yml` with a new `PID-<CAT>-NNN` id.
2. Fill every field: `name`, `category`, `severity`, `lang`, `flags`, `pattern`,
   `maps_to` (OWASP LLM / MITRE ATLAS), `false_positive`, `description`.
3. **Every rule must have an honest `false_positive` note.** Pattern matching has a
   real FP tax; say where this one over-fires.
4. Run the checks locally:
   ```bash
   pip install -r requirements-dev.txt
   python validate.py           # schema + regex compile + self-test
   python scan.py <<< "your test string"
   ```
5. Open a PR. CI runs `validate.py` on every push.

## Guidelines
- Prefer precise patterns over broad ones; a noisy rule set gets turned off.
- Map to a framework where possible.
- Keep it visible-text only — invisible/codepoint payloads belong in
  [uncloak](https://github.com/fevziegeyurtsevenler/uncloak).
