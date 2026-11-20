# update-review: reference

Everything the [skill](SKILL.md) compresses: the rule catalogue, what the extractor actually reads,
the baseline format, and the honest limits.

## Commands

```bash
python3 skills/update-review/scripts/update_review.py selftest
python3 skills/update-review/scripts/update_review.py snapshot --root . [--out PATH]
python3 skills/update-review/scripts/update_review.py check    --root . [--baseline PATH] \
        [--base-ref origin/main] [--json] [--report PATH]
python3 skills/update-review/scripts/update_review.py approve  --root . --by <login> \
        [--commit SHA] [--note "why"]
```

Stdlib only, Python 3.9+, no network, no git required except `--base-ref` and the commit lookup in
`approve`. Exit codes for `check`: `0` PASS, `2` MANUAL_REVIEW, `3` REJECT, `1` tool error.

## Rule catalogue

`verdict` decides the gate. `severity` only orders the report.

| Rule | Verdict | Severity | Fires when |
|---|---|---|---|
| `rug.hidden-instruction` | REJECT | critical | A prompt/doc gains "ignore previous instructions", "don't tell the user", "silently", bidi controls, zero-width characters, or an HTML comment addressed to an agent |
| `rug.curl-pipe-shell` | REJECT | critical | `curl`/`wget` output is piped into a shell |
| `rug.exfiltration-pair` | REJECT | critical | The same unit gains both a credential read and an outbound channel |
| `rug.autonomy-raise` | REJECT | critical | `L4`/`L5`, auto-merge, merge-without-review, bypass-protection, "treat this as approved" |
| `rug.ci-permission-widening` | REJECT | critical | A workflow grants a `write` scope the baseline did not have |
| `rug.untrusted-checkout` | REJECT | critical | `pull_request_target` appears |
| `rug.identity-swap` | REJECT | critical | `plugin.json` / `marketplace.json` points the repository or homepage at a new host |
| `rug.destructive-command` | REJECT | critical | `rm -rf /`, disk format, fork bomb |
| `rug.new-egress` | MANUAL_REVIEW | high | A new outbound channel: upload POST, netcat, ssh/scp/rsync, DNS query |
| `rug.new-secret-read` | MANUAL_REVIEW | high | A new credential read: env dump, `.ssh`/`.env`/`.aws`, token names, `${{ secrets.* }}`, keychain |
| `rug.outside-write` | MANUAL_REVIEW | high | A new write outside the repo, `sudo`, `chmod +x`, force-push |
| `rug.obfuscation` | MANUAL_REVIEW | high | A new base64/hex/`\xNN` blob of 40+ characters per token or 120+ bytes |
| `rug.dynamic-execution` | MANUAL_REVIEW (prompt, doc) / INFO (script) | high / low | `eval`, `exec`, `subprocess`, `child_process` |
| `rug.secret-in-run` | MANUAL_REVIEW | high | `${{ secrets.* }}` interpolated into a workflow shell step |
| `rug.new-binary` | MANUAL_REVIEW | high | A binary file appears under `skills/` or `automations/` |
| `rug.unpinned-action` | MANUAL_REVIEW | medium | `uses: owner/repo@ref` without a 40-hex SHA, from an owner outside the allowlist |
| `drift.guardrail-removed` | MANUAL_REVIEW | medium | The unit lost a guardrail clause and gained a capability in the same update |
| `drift.payload-growth` | MANUAL_REVIEW | high | Bytes ≥ 2× the baseline and ≥256 KB larger, or more than 400 files |

Refactors, renames, wording changes, added explanations and reordered files produce no finding:
every rule compares *new tokens* against the baseline's tokens for that path.

## What the extractor reads

Per file it records `kind`, `bytes`, `lines`, `sha256`, `binary`, and a `signals` map of
`group → {token: first line}`:

| Group | Tokens |
|---|---|
| `sinks` | `pipe-to-shell`, `http-upload`, `netcat`, `ssh-remote`, `dns-exfil`, `base64-decode`, `eval-dynamic` |
| `secrets` | `env-dump`, `secret-file`, `token-name`, `ci-secret`, `keychain` |
| `outside-write` | `outside-path`, `destructive`, `privilege`, `force-push` |
| `hidden` | `ignore-previous`, `no-disclosure`, `silent-mode`, `html-comment`, `bidi-control`, `zero-width` |
| `autonomy` | `raise`, `grant` |
| `ci` | `untrusted-checkout`, `permission-write`, `secret-in-run` |
| `obfuscation` | `base64-blob`, `hex-blob`, `escaped-bytes` |
| `domains` | every URL host and `user@host` target |
| `tools` | MCP-style tool ids (`github/create_issue`, `shell/run`) |
| `unpinned` | `owner/repo@ref` from `uses:` where ref is not a commit SHA |
| `guardrails` | `read-only`, `never-push`, `never-merge`, `never-write`, `never-delete`, `no-secrets`, `must-not` |

`unit` groups related files: `skills/<name>`, `automations/<name>`, `.github/<dir>`, else the top
directory. Pairing (exfiltration, guardrail drift) happens per unit, so a credential read in
`SKILL.md` and a POST in `scripts/sync.py` still pair.

## Baseline format

```json
{
  "schema": 1,
  "generated_at": "2026-11-13T10:00:00Z",
  "approved_commit": "9f2c1e4…",
  "approved_at": "2026-11-13T10:00:00Z",
  "approved_by": "anglelion",
  "policy": {
    "max_files": 400,
    "max_bytes": 8000000,
    "max_growth_ratio": 2.0,
    "min_growth_bytes": 262144,
    "allowed_action_owners": ["actions", "github"],
    "ignore_paths": []
  },
  "aggregate": {"files": 82, "bytes": 372000, "kinds": {"skill": 17, "doc": 6}},
  "files": {
    "skills/update-review/SKILL.md": {
      "kind": "skill", "bytes": 6421, "lines": 128, "binary": false,
      "sha256": "…",
      "signals": {"sinks": {"curl-pipe-shell": 74}, "guardrails": {"read-only": 12}}
    }
  },
  "history": [
    {"commit": "9f2c1e4…", "approved_at": "2026-11-13T10:00:00Z",
     "approved_by": "anglelion", "note": "v0.2.0", "files": 82}
  ]
}
```

The baseline is committed and reviewed like any other file. `history` keeps the last 20 approvals:
which human, which commit, what they said. That list is the audit trail a "who approved this version"
question needs.

## CI wiring

`.github/workflows/update-review.yml` in this repo runs `selftest`, then `check`, uploads the JSON
report and comments the verdict on the PR. Both non-zero codes fail the job. To make it a real gate,
mark `update review / recheck` as required in the branch protection rule; a failing check nobody must
pass is a notification, not a gate.

Two rules for the workflow itself, since it is reviewed by the same tool:

- Pin third-party actions to a commit SHA. First-party `actions/*` and `github/*` may use tags.
- Keep `permissions:` at `contents: read` plus what the comment step needs. The tool treats a new
  `write` scope as blocking, because a workflow cannot grant itself more than the token already has.

On a fork PR, `pull_request` runs with a read-only token and no secrets, which is why the workflow
never uses `pull_request_target`. Keep it that way.

## Limits, stated plainly

- **Signals, not semantics.** The extractor matches text. A capability expressed in prose the patterns
  do not know ("send the config to our analytics partner") passes. Pair with
  [`cross-model-review`](../cross-model-review/SKILL.md) on the changed files when the update matters.
- **New, not total.** A rule fires on a capability the baseline lacked. An update that *uses* an
  already-approved capability in a new way is invisible here. That is the deliberate trade: silence on
  refactors is what makes the loud verdicts credible.
- **The baseline is the trust anchor.** Whoever can edit `baseline.json` can approve anything, including
  through a PR that also adds the payload. Require review on `.lever/**` (CODEOWNERS) and re-run `check`
  on the merge commit. `approve` after merge, never before.
- **Prompt files are data.** A model reading a skill can be told anything by that skill. Treat
  `MANUAL_REVIEW` as "another model reads this with the baseline in hand", not as "probably fine".
- **Large assets.** Vendored binaries and images blow past the growth threshold. Exclude them in
  `policy.ignore_paths`, or accept the `drift.payload-growth` review each time.
