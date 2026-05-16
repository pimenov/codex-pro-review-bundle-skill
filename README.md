# Codex Pro Review Bundle Skill

A Codex skill for packaging complex plans into a compact, secret-aware markdown bundle that can be reviewed by ChatGPT Pro before implementation.

It is designed for work where a missed nuance is expensive: production-adjacent changes, architecture decisions, client proposals, data migrations, external integrations, and multi-module refactors.

## Why This Exists

Codex is strong at doing the work in the local environment. GPT Pro can be useful as a slower second reviewer when the plan is risky, cross-functional, or easy to over-scope.

This skill creates a review packet with:

- explicit risk tiers
- a privacy gate
- allowlisted file inclusion
- secret and PII heuristics
- bundle completeness status
- a post-review decision log

The goal is not to outsource judgment. The goal is to make the judgment loop harder to fool.

Contributions are welcome. Please use synthetic examples only and never include real secrets, client data, production logs, browser profiles, or personal data in issues or pull requests.

## Install

Clone the repo and copy the skill folder into your Codex skills directory:

```bash
git clone https://github.com/pimenov/codex-pro-review-bundle-skill.git
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R codex-pro-review-bundle-skill/pro-review-bundle "${CODEX_HOME:-$HOME/.codex}/skills/"
```

Restart Codex or open a new Codex session after installing.

## Usage

Ask Codex:

```text
Use $pro-review-bundle.

Build a safe GPT Pro review bundle for the current plan.
Classify privacy/risk, include only the minimum needed files, and stop if the bundle is incomplete or may leak secrets.
```

Or run the script directly:

```bash
python3 "${CODEX_HOME:-$HOME/.codex}/skills/pro-review-bundle/scripts/build_bundle.py" \
  --root /path/to/project \
  --title "Review deployment plan" \
  --task-file /path/to/review-request.md \
  --include AGENTS.md \
  --include README.md \
  --include "docs/**/*.md" \
  --output /tmp/pro-review-bundle.md
```

The bundle should only be sent to ChatGPT Pro when the manifest says:

```text
Completeness: COMPLETE
```

If there are warnings, skipped files, unmatched includes, possible PII, or redactions, treat the bundle as incomplete until a human reviews the issue.

## Safety Model

The included builder is conservative by default:

- blocks broad globs like `**/*`
- blocks files outside `--root` unless explicitly allowed
- denies common sensitive directories and file patterns
- scans for secret-like values and PII-like values
- exits non-zero when warnings or skips are present unless `--allow-warnings` is explicit
- can redact secret-like values with `--redact-secrets`

This is a helper, not a formal security boundary. Always inspect the generated bundle before pasting it into any external model.

## Repository Layout

```text
pro-review-bundle/
  SKILL.md
  agents/openai.yaml
  references/review-prompt-template.md
  scripts/build_bundle.py
```

## Test Locally

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

## Inspiration

This repo was prompted by Aniket Panjwani's public note about using GPT Pro more deliberately as a high-depth reviewer for complex work.

What comes from that inspiration:

- use GPT Pro as a skeptical second reviewer before execution
- package enough context for a useful review
- keep review separate from implementation approval

What this repo adds:

- an installable Codex skill
- explicit risk tiers and a privacy gate
- an allowlist-based bundle builder
- secret and PII heuristics
- a `COMPLETE` / `INCOMPLETE` bundle manifest
- a post-review decision log
- contribution and security guidance for public use

This project is independent and does not copy code, prompts, or assets from Aniket Panjwani, OpenAI, or any third-party workflow/tool mentioned above.

## License

MIT
