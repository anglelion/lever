# update-review automation

**Purpose.** Every update to this repo is a capability change someone should have read. The automation
runs the deterministic check from [`skills/update-review`](../../skills/update-review/SKILL.md) on the
updates that matter — `skills/**`, `automations/**`, `plugin.json`, `.github/**` — and posts one verdict.
It never approves, never merges and never edits the baseline: a human does that, in a PR whose diff is
the approval.

This is the cloud half of update review. The baseline is the memory; the gate is the signal; the
`history` array in `.lever/update-review/baseline.json` is the audit trail.

## Triggers

| Trigger | Filter | Why |
|---|---|---|
| `pull_request` opened | paths: `skills/**`, `automations/**`, `plugin.json`, `.github/**` | the update arrives reviewable |
| `pull_request` synchronize | same paths, `-is:draft` | new commits on the same PR; skip drafts |
| `push` to the default branch | — | catches an update that landed without a PR |

Do not add a per-push trigger without the draft filter: review runs per PR go up **~2–3×** and the
verdict is the same on every push.

## Least privilege

Read tools only, plus one comment tool:

- read the PR, its files and the repo at the head SHA
- run `python3 skills/update-review/scripts/update_review.py check` in the checked-out workspace
- `github/add_issue_comment` / `github/create_issue` (for a non-PASS verdict)
- nothing that writes code, merges, approves or edits `.lever/**`

## Dials

| Dial | Default | Options |
|---|---|---|
| `MODE` | `act` | `dry_run` = compute, record, post nothing |
| `FAIL_ON` | `reject` | `manual_review` (stricter), `none` (report only) |
| `COMMENT` | one per head SHA, edited in place | never |
| `PATHS` | `skills/**`, `automations/**`, `plugin.json`, `.github/**` | narrow for single-plugin repos |
| `RUN_SELFTEST` | true | false only if the workspace is read-only |
| [Spend](../../docs/spend.md) | standard | the tool is deterministic; a model reads the report, not the tree |

## Outcome metric

- **Primary:** blocking findings a human kept / blocking findings posted. A finding reverted out of
  caution counts against it.
- **Escapes:** an update that reached the default branch with a capability the next `check` calls new.
  Every escape is a missing rule. Add the rule before the next release.
- **Silence rate:** the share of runs that end `NOOP`. It should be high; if it drops, the paths filter is
  too wide or the extraction went noisy.
- **Time to verdict:** the tool takes about a second on a repo this size. A slow run means the workspace
  is being re-cloned, not re-read.

## Install via GitHub MCP

1. Run [`automate-it`](../../skills/automate-it/SKILL.md) and paste [prompt.md](prompt.md) with
   `MODE: dry_run`.
2. Create it paused, with the triggers above, a read-only tool set plus one comment tool, and
   `write_scope: repository` only if it files issues.
3. Dry-run three historical updates, comparing each verdict with what a human concluded at the time.
4. Enable on approval. Pair it with an [improver](../improver/README.md):
   `GOOD_OUTCOME: finding reverted or fixed before merge`,
   `BAD_OUTCOME: finding overridden as a false positive`.

## What broke while tuning, so you can skip it

- Posting a comment on every push buried the PR. One comment per head SHA, edited in place.
- A `PASS` comment trained people to ignore the bot. Silence is the pass.
- Without the `-is:draft` filter the run count tripled and the reports were identical.
- The automation once "helpfully" updated the baseline after a clean run. That made the gate approve its
  own updates; the baseline is a human command now.
- A repo that vendored images tripped the growth rule every release. `ignore_paths` fixed it; loosening
  the threshold would not have.
