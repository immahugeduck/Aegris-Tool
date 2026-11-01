# Aegris

Point Aegris at a GitHub repository and it will:

1. **Scan** it with three standard open-source scanners:
   - [gitleaks](https://github.com/gitleaks/gitleaks) finds passwords, API keys and tokens written into the code or buried in git history.
   - [semgrep](https://semgrep.dev) finds dangerous code patterns such as SQL injection, shell injection, `eval`, and disabled TLS checks.
   - [osv-scanner](https://google.github.io/osv-scanner/) finds dependencies with published vulnerabilities (CVEs).
   - Aegris adds its own checks for committed `.env` files and unsafe GitHub Actions workflows.
2. **Add baseline protection** that's missing: Dependabot for automatic dependency updates, `.gitignore` rules for secret files, and a `SECURITY.md`.
3. **Fix** the findings using Claude Code, with minimal changes and real package-manager upgrades.
4. **Re-scan** to prove what actually got fixed. The report only counts a finding as fixed if the scanner no longer sees it.
5. **Open a pull request** on that repo with a plain-English report. Nothing is merged without you.
6. **Come back every 30 days.** Each project gets its own 30-day timer. The re-review updates the same PR rather than piling up new ones.

```
 you: "review owner/repo"
        │
        ▼
 ┌──────────┐   ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌──────────────┐
 │  scan    │──▶│  harden  │──▶│ Claude    │──▶│ re-scan  │──▶│ PR + report  │
 │ 3 tools  │   │ baseline │   │ fixes     │   │ (verify) │   │ on the repo  │
 └──────────┘   └──────────┘   └───────────┘   └──────────┘   └──────┬───────┘
                                                                     │
       registry/projects.json  ◀── next review = today + 30 days ────┘
       (checked daily by the scheduled workflow)
```

---

## One-time setup (about 10 minutes)

Aegris runs on GitHub Actions in *this* repo and reaches out to your other repos. That needs two keys stored as **repository secrets**: Settings → Secrets and variables → Actions → New repository secret.

### 1. `AEGRIS_TOKEN`: lets Aegris open PRs on your other repos

GitHub's built-in workflow token can only touch the repo the workflow lives in, so Aegris needs its own token.

1. Go to GitHub → your avatar → **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**.
2. **Repository access**: pick *Only select repositories* and choose the repos you want Aegris to review. You can edit this list later.
3. **Permissions** (Repository permissions):
   | Permission | Access | Why |
   |---|---|---|
   | Contents | Read and write | clone the code and push the fix branch |
   | Pull requests | Read and write | open/update the PR |
   | Issues | Read and write | file an issue when there's a finding but nothing to change in code |
   | Workflows | Read and write | Aegris fixes insecure files in `.github/workflows/`, and GitHub refuses pushes that touch those without this |
   | Metadata | Read | required by GitHub |
4. Set an expiration; a year is reasonable. Put a reminder on your calendar, because Aegris stops working when it expires and the workflow log will say so.
5. Save it as a secret named `AEGRIS_TOKEN` in this repo.

### 2. Claude access: pick **one**

- **`ANTHROPIC_API_KEY`**: an API key from [console.anthropic.com](https://console.anthropic.com). You're billed per use.
- **`CLAUDE_CODE_OAUTH_TOKEN`**: uses your Claude subscription instead. Run `claude setup-token` on your own computer and paste the result in as the secret.

Without either one, Aegris still scans, adds the baseline protections and opens the PR; it just skips the AI fix step.

### 3. Optional settings (Settings → Secrets and variables → Actions → **Variables** tab)

| Variable | Default | What it does |
|---|---|---|
| `AEGRIS_MAX_BUDGET_USD` | `5` | Hard cap on AI spend **per project per review**. Claude Code stops when it hits this. |
| `AEGRIS_MODEL` | Claude Code's default | Which Claude model does the fixing. |

---

## Using it

### Point it at a project

**Actions** tab → **Aegris security review** → **Run workflow** → type the repo as `owner/name` (e.g. `immahugeduck/central-command`) → **Run**.

That project is now registered. It gets reviewed right away, and then again every 30 days without you doing anything.

### What you get back

A pull request titled **"Aegris: security fixes"** on the target repo, containing:

- a summary table: found / fixed and verified / still open
- **⚠️ Action needed from you**: exposed credentials you must rotate. Code changes can't un-leak a key that's already been pushed; only revoking it with the provider (Stripe, AWS, etc.) does.
- Claude's notes: *What I changed*, *Skipped* (and why), and *Needs a human*
- full tables of fixed and remaining findings

Review it like you'd review a contractor's work before signing off. **Read the diff, then merge.** Automated fixes are usually right and occasionally wrong.

If a review finds problems but has nothing to change in code (e.g. only old secrets in git history), you get an **issue** instead of a PR. If the repo is clean, nothing is opened and the registry just records "clean".

### The 30-day cycle

`registry/projects.json` is the logbook: every project, when it was last reviewed, when it's next due, and the last 12 results. A scheduled run checks it every morning and reviews whatever is due. After each run the workflow commits the updated logbook back to this repo, so the history is in git.

| To... | Do this |
|---|---|
| review a project now, out of cycle | Run workflow with its name again |
| pause a project | set `"paused": true` on it in `registry/projects.json` |
| stop reviewing a project | delete its entry (or run `python -m aegris remove owner/name` and commit) |
| change the interval for everything | edit `"interval_days"` at the top of the file |
| see results | Actions tab → a run → **aegris-reports** artifact (kept 90 days) |

### Running it on your own computer

Requires Python 3.10+, git, and the scanners (`bash scripts/install-scanners.sh` installs them on Linux; on Mac use `brew install gitleaks osv-scanner semgrep`).

```bash
python -m aegris scan ./some-project            # report only, changes nothing
python -m aegris run ./some-project --no-ai     # baseline + report, no AI
python -m aegris run ./some-project             # full run; needs `claude` installed and logged in / API key set
```

On a local folder Aegris edits the files in place and does **not** commit. Look at `git diff`, keep what you like, and commit it yourself.

---

## Safety design (why it's built the way it is)

Aegris works on code it didn't write, which may contain text designed to trick an AI ("ignore your instructions and…"). So:

- **Claude never gets the GitHub token.** The fix step runs with a scrubbed environment containing only the Claude credential and basic system variables. Cloning and pushing are done by Aegris itself, with the token passed per command and never written to disk inside the cloned repo.
- **Claude gets a short tool list**: read/edit files, package-manager upgrade commands, and build/test commands. No git, no curl, no web access. Anything else is refused outright, not asked about.
- **The target repo's own Claude settings are ignored** (`.claude/settings.json`, hooks, `.mcp.json`), so a repo can't grant itself extra powers.
- **Nothing is trusted on Claude's word.** The re-scan decides what counts as fixed.
- **Scanner downloads are pinned** to exact versions and checked against SHA-256 checksums.
- **Spend is capped** per project per run (`AEGRIS_MAX_BUDGET_USD`).

One honest caveat: build and test commands (`npm install`, `npm test`, …) run the project's own scripts. That's inherent to checking a fix doesn't break anything. It happens on a throwaway GitHub runner with no GitHub token in reach, but this is a tool for **your own repos**, not for running on strangers' code.

## Limits, plainly

- **It can't rotate leaked credentials.** It tells you which ones and where; you revoke them with the provider.
- **It doesn't rewrite git history.** A secret that was ever pushed stays in history; rotation is the fix.
- **Scanners miss things.** This catches the common, well-known problems. It is not a penetration test, and a clean report doesn't mean "secure".
- **Major-version dependency upgrades are often skipped** on purpose when they could break your app. The PR says which ones and why.
- **Costs** (estimates, not quotes): in testing, fixing 13 findings in a small repo cost about $0.23 of AI usage as reported by Claude Code. Bigger repos with many findings cost more, up to your cap. GitHub Actions minutes come out of your plan's monthly allowance for private repos; check your plan's current quota on GitHub's billing page.

## Development

```bash
python -m pip install pytest
python -m pytest -q          # unit tests + end-to-end scanner tests (skipped if scanners missing)
python -m aegris scan . --fail-on high   # Aegris checks itself in CI
```

Set `AEGRIS_SEMGREP_REGISTRY=""` to use only the built-in rules in `aegris/rules/`. This helps offline or on networks that block semgrep.dev.

| Path | What it is |
|---|---|
| `aegris/cli.py` | commands and the scan → harden → fix → verify → PR pipeline |
| `aegris/scanners.py` | runs gitleaks / semgrep / osv-scanner and normalizes their output |
| `aegris/hardening.py` | Aegris's own config checks and the baseline files it adds |
| `aegris/fixer.py` + `prompts/fix.md` | the Claude Code fix step and its instructions |
| `aegris/github.py` | clone / push / PR / issue |
| `aegris/registry.py` | the 30-day logbook |
| `aegris/rules/` | built-in semgrep rules (always run, alongside semgrep's public `p/default` pack) |
| `.github/workflows/aegris.yml` | the daily schedule and the "Run workflow" button |
