# Secret Scanner Action

A GitHub Action that scans pull requests for leaked secrets — API keys, tokens, private keys, and database credentials — before they hit production.

Runs automatically on every PR, fails the check if a secret is found, and comments directly on the PR with the file, line, and type of each finding.

## Why

Existing tools like GitGuardian and TruffleHog are great but heavy. This is a lightweight, self-hosted, zero-dependency-on-external-services alternative you can drop into any repo in two minutes.

## How it works

1. **Pattern matching** — checks changed lines against known formats for AWS keys, GitHub/GitLab tokens, Stripe keys, Slack tokens/webhooks, Google API keys, JWTs, private key blocks, DB connection strings, and more.
2. **Entropy detection** — flags high-entropy strings that don't match any known format, catching secrets pattern matching alone would miss.
3. **PR comment** — posts (and updates, on re-push) a single comment summarizing findings with redacted values.

## Usage

Add this workflow to `.github/workflows/secret-scan.yml`:

```yaml
name: Secret Scan

on:
  pull_request:
    branches: [main, master]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Secret Scanner
        uses: your-username/secret-scanner-action@v1
        with:
          scan-mode: diff        # 'diff' (default) or 'full'
          fail-on-found: true    # fail the check when secrets are found
```

## Configuration

Copy `.secretscan.yml.example` to `.secretscan.yml` at your repo root to ignore known false positives:

```yaml
ignore:
  paths:
    - "test/fixtures/**"
  strings:
    - "AKIAEXAMPLE0000000"
```

## Inputs

| Input | Description | Default |
|---|---|---|
| `github-token` | Token used to post PR comments | `${{ github.token }}` |
| `scan-mode` | `diff` (changed files only) or `full` (whole repo) | `diff` |
| `fail-on-found` | Fail the check if secrets are found | `true` |

## Outputs

| Output | Description |
|---|---|
| `findings-count` | Number of potential secrets found |
| `findings` | JSON array of all findings |

## Local development

```bash
npm install
npm test          # run the test suite
npm run build     # bundle src/index.js -> dist/index.js
```

The Action runs `dist/index.js`, so always run `npm run build` before committing changes to `src/`.

## Roadmap

- [ ] Custom pattern definitions via config
- [ ] Baseline/fingerprint file to suppress previously-approved findings
- [ ] SARIF output for GitHub code scanning integration
- [ ] Docker-based version for non-Node environments

## License

MIT
