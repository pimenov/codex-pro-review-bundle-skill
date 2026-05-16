# Contributing

Contributions are welcome, especially when they make the bundle builder safer, clearer, or easier to install.

Good contribution areas:

- better secret and PII heuristics
- fewer false positives without weakening safety
- safer default deny patterns
- clearer installation instructions for Codex users
- examples using synthetic data
- bug reports with minimal reproductions

Please do not include real secrets, production data, private client material, raw logs, browser profiles, or personal data in issues, pull requests, tests, or examples.

## Local Checks

Run these before opening a pull request:

```bash
python3 -m py_compile pro-review-bundle/scripts/build_bundle.py

python3 pro-review-bundle/scripts/build_bundle.py \
  --root pro-review-bundle \
  --title "Smoke test" \
  --task "Privacy Classification: PUBLIC. Goal: verify this public skill package." \
  --include SKILL.md \
  --include references/review-prompt-template.md \
  --output /tmp/pro-review-bundle-smoke.md
```

The smoke bundle should report:

```text
Completeness: COMPLETE
```

## Pull Request Notes

In the pull request, include:

- what changed
- why it is safer or clearer
- what checks you ran
- any known limitations
