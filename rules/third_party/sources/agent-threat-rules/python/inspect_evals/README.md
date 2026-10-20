# ATR Inspect wrapper

UK AISI [Inspect](https://inspect.aisi.org.uk/) `@task` wrapper for the Agent Threat Rules (ATR) corpus.

This wrapper is independent of the `pyatr` package -- it loads ATR YAML rules directly via PyYAML and compiles the detection regexes with Python's `re` module, so the only runtime dependencies are `inspect-ai` and `pyyaml`.

## Install

```
pip install inspect-ai pyyaml
```

## Run

From the repo root:

```
inspect eval python/inspect_evals/inspect_task.py:atr_prompt_injection --limit 10
```

To run the full corpus (300+ samples drawn from `rules/**/*.yaml` `test_cases.true_positives`):

```
inspect eval python/inspect_evals/inspect_task.py:atr_prompt_injection
```

To smoke-test rule loading and dataset construction without Inspect's runner:

```
python python/inspect_evals/inspect_task.py
```

## What it does

Loads ATR YAML rules directly via `yaml.safe_load`, compiles every `detection.conditions[].value` where `operator == regex` into a `re.Pattern`, samples up to 4 canonical adversarial prompts per rule from `test_cases.true_positives`, and scores 1.0 if any compiled ATR pattern matches the sample text.

The default solver echoes the sample input as the completion, which gives a corpus-coverage score (does ATR's pattern set match the adversarial prompts it ships with). Swap `echo_input()` for `generate()` and pass `--model <provider/model>` to score ATR detection on a model's output instead.

## Categories covered

Samples are drawn across the 10 ATR categories:

- prompt-injection
- tool-poisoning
- context-exfiltration
- agent-manipulation
- privilege-escalation
- excessive-autonomy
- data-poisoning
- model-abuse
- skill-compromise
- model-security

## Notes on regex compatibility

ATR rule patterns are authored against the TypeScript engine (JavaScript-flavoured regex). The wrapper compiles each pattern via `re.compile` and skips any pattern Python rejects. In practice the skipped subset is small (a handful of JS-only constructs); coverage from the remainder is what the wrapper reports.

## License

MIT, same as the rest of ATR.
