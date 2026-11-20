---
name: update-review
user-invocable: false
description: Reviews an update against the last approved baseline and reports only the capability that changed — new tools, hosts, credential reads, outbound channels, destructive commands, hidden instructions, autonomy raises, CI permission widening. Built for rug pulls: a version that is fine when approved and hostile when it lands. Use when a repo, plugin, skill or automation moves to a new version, when asked "is this update safe?", "what changed since we approved it?", "check for a rug pull", or when wiring a merge gate that must stay quiet on refactors and loud on capability.
---

# Update review

An approved version is a promise about behaviour. An update either keeps the promise or quietly
edits it. Reading the diff answers "what text changed"; it does not answer "what can this thing now
do that it could not do before". That second question is the one a rug pull exploits: the update is
small, plausible and reviewed by skim, and the capability it adds is the payload.

This skill answers the second question. `snapshot` records the capability signals of the approved
tree; `check` extracts them again and diffs; the rules fire only on a *new* capability. A refactor,
a rename or a rewritten paragraph stays quiet. One added `curl … | sh`, one newly read token, one
widened CI permission is a verdict.

Deterministic first. The script does the diffing and the rule evaluation, because that part has an
answer. The model reads the findings and decides, because that part does not.

## When to use / not use

Use it:
- when a repo, plugin, skill or automation moves to a new version and someone asks whether it is safe;
- before merging a PR that touches `skills/**`, `automations/**`, `plugin.json`, `.github/**`;
- when a dependency's install instructions changed and the install is what runs;
- as the gate on a repo whose updates arrive from outside your team;
- after a takeover: recount what the new maintainers can now do.

Don't use it:
- as a substitute for reading a diff that adds logic. Capability diffing finds the payload; it does not
  prove the algorithm is right. Pair it with [`cross-model-review`](../cross-model-review/SKILL.md);
- on the first version of anything. There is no promise yet. Approve a baseline first;
- to bless a change it just flagged. A human approves; the tool never approves itself.

## Steps

1. **Find the baseline.** `git log -- .lever/update-review/baseline.json` and
   `git show HEAD:.lever/update-review/baseline.json` tell you which commit was last approved and by
   whom. No baseline: this is a first version — say so, and offer `snapshot` + `approve` instead of a
   verdict. Do not invent a baseline from the current tree; that approves the update by definition.
2. **Run the check.**

   ```bash
   python3 skills/update-review/scripts/update_review.py check --root . --report update-review.md
   ```

   On a PR whose baseline is younger than the branch point, add `--base-ref origin/main` to diff
   against that ref instead of the committed baseline. `--json` prints the machine-readable result.
   Exit code carries the verdict: `0` PASS, `2` MANUAL_REVIEW, `3` REJECT. Any non-zero means stop.
3. **Read the findings as capability, not as style.** For each `REJECT`, name the line and say what it
   lets the thing do that it could not do before. Do not soften a blocking rule into "worth noting":
   the rules are the promise.
4. **Check the diff for intent once the tool has narrowed it.** `git diff <baseline>..<update>` on the
   files the findings name, and on nothing else. Ask the question the rules cannot: does this update
   change who receives the data, or who the user thinks is running it?
5. **Decide.**
   - `REJECT`: revert, or split the capability into its own PR with its own review, then re-run.
   - `MANUAL_REVIEW`: a human reads the named lines and either reverts or approves deliberately.
   - `PASS`: merge.
6. **Approve only the code that will run.** After the update lands on the default branch, and after a
   human has said yes:

   ```bash
   python3 skills/update-review/scripts/update_review.py approve --by <github-login> --note "why"
   ```

   That commit carries the new `baseline.json`. Approving before merge approves a tree nobody runs;
   approving after a revert approves the thing you rejected.
7. **Report** in three lines: baseline commit, verdict, the rules that fired. Then the one sentence a
   reviewer needs: what this update can do that the approved one could not.

## Verdicts

| Verdict | Exit | Meaning | Who acts |
|---|---|---|---|
| `PASS` | 0 | No new capability in any watched group. | Merge. |
| `MANUAL_REVIEW` | 2 | A new channel, credential read, unpinned action, obfuscated blob, dropped guardrail, or repo growth. Not proof of malice; not a pass either. | A human reads the named lines. |
| `REJECT` | 3 | A blocking rule fired: hidden instruction, piped download, exfiltration pair, autonomy raise, CI permission widening, `pull_request_target`, identity swap, destructive command. | Revert or split. Never "approve anyway". |

Both non-zero codes are non-zero on purpose: a gate that passes a "look at this" verdict is not a gate.

## What the rules watch

Full table and extraction details: [`reference.md`](reference.md). The short version:

- **Hidden instructions** in prompt files, including bidi and zero-width characters and HTML comments
  addressed to an agent. Prompts are executable text here; an instruction to hide is the payload.
- **Download piped to a shell**, and eval/exec of runtime content from inside a skill or doc.
- **A credential read paired with an outbound channel** in the same unit (a skill folder, an automation),
  even across two files. Either alone is a review; together they are exfiltration.
- **Autonomy raises**: `L4`/`L5`, auto-merge, "merge without approval", "treat this as approved".
  Only the user's dial sets that.
- **CI widening**: new `pull_request_target`, new `write` scope, `${{ secrets.* }}` in a run step.
- **Identity swaps** in `plugin.json` / `marketplace.json`: the repository or homepage host moved.
- **Destructive commands**: `rm -rf /`, disk format, force-push.
- **Drift**: a guardrail clause (`read-only`, `never push`, `no secrets`) removed in the same unit that
  gained a capability; the repo doubling in bytes or files.

## Dials

| Dial | Default | Options |
|---|---|---|
| Baseline | `.lever/update-review/baseline.json` in the repo | any path; one baseline per repo |
| Gate | exit 2 and 3 both fail CI | fail on `REJECT` only, at your own risk |
| Report | markdown to stdout, `--json` for machines | `--report path.md\|.json` |
| Unpinned-action allowlist | `actions/*`, `github/*` | add owners you actually trust |
| Growth threshold | 2× bytes and ≥256 KB, or >400 files | raise for asset-heavy repos |
| Second reader | off | `cross-model-review` on the changed files |
| Autonomy | L0 for the verdict: it never approves | `approve` is a human command |

## Outputs

- A report: baseline commit, verdict, findings with `path:line`, and what to do.
- `--json` with `verdict`, `changes`, `changed_paths`, `findings[]` for a CI step or a bot comment.
- A new `baseline.json` when a human approves, with one `history` entry per approval.

## This skill's own feedback loop

- **False REJECT rate:** replays where a human overrode a blocking rule. Above ~1 in 20, the rule is
  wrong, not the update. Tighten the rule; do not loosen the gate.
- **Escapes:** a capability that reached the default branch without a finding. Every escape is a missing
  pattern or a group the extraction never looked at. Add the rule before the next release.
- **Noise:** share of `MANUAL_REVIEW` verdicts that ended in "this was fine". High noise trains people
  to click through, which is the failure this replaces.
- **Review time per update:** should fall as the tool narrows the diff. If it rises, the report is
  naming files instead of capabilities.

## Failure modes it prevents

- A one-line prompt edit that reads a token and posts it, approved because "the diff was tiny".
- An automation whose prompt gains a trigger it never had, so it now runs on every push.
- A workflow switched to `pull_request_target` to "fix" a permissions error.
- A dependency whose install script changed from a pinned tarball to `curl | sh`.
- A repo that changed hands, kept the layout, and pointed the homepage at a new host.
- Review fatigue: every update read as prose, so the one that matters reads the same as the rest.

## Why this exists

- The dangerous update is rarely a large one. It is one line in a file humans classify as documentation
  and agents execute as instructions. Diff size is the wrong signal; capability is the right one.
- A baseline is what makes "new" computable. Without it, every review re-reads everything and the
  reviewer's attention is the scarce resource. With it, the report is one page and names the change.
- Deterministic rules are cheap and reproducible; a model reading a diff is neither. Extract first, judge
  second, and keep the verdict recomputable from two JSON snapshots.
