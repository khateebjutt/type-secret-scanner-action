const core = require('@actions/core');
const github = require('@actions/github');
const { execSync } = require('child_process');
const path = require('path');
const { loadConfig, scanFiles, scanRepo } = require('./scanner');

const COMMENT_MARKER = '<!-- secret-scanner-action -->';

async function run() {
  try {
    const repoRoot = process.env.GITHUB_WORKSPACE || process.cwd();
    const failOnFound = core.getBooleanInput('fail-on-found') ?? true;
    const scanMode = core.getInput('scan-mode') || 'diff'; // 'diff' | 'full'
    const token = core.getInput('github-token') || process.env.GITHUB_TOKEN;

    const config = loadConfig(repoRoot);
    core.info(`Loaded config: ${config.ignorePaths.length} ignored path patterns, ${config.ignoreStrings.length} ignored strings`);

    const context = github.context;
    const isPR = context.eventName === 'pull_request' || context.eventName === 'pull_request_target';

    let findings = [];

    if (scanMode === 'full' || !isPR) {
      core.info('Running full repository scan...');
      findings = scanRepo(repoRoot, config);
    } else {
      core.info('Running diff-based scan on changed files...');
      const changedFiles = getChangedFiles(context, repoRoot);
      core.info(`Changed files: ${changedFiles.length}`);
      const fullPaths = changedFiles.map((f) => path.join(repoRoot, f));
      findings = scanFiles(fullPaths, repoRoot, config);
    }

    core.info(`Scan complete. ${findings.length} finding(s).`);

    core.setOutput('findings-count', String(findings.length));
    core.setOutput('findings', JSON.stringify(findings));

    if (findings.length > 0) {
      printSummary(findings);
    }

    if (isPR && token) {
      await postOrUpdatePRComment(context, token, findings);
    }

    if (findings.length > 0 && failOnFound) {
      core.setFailed(`Secret scan found ${findings.length} potential secret(s). See job summary for details.`);
    }
  } catch (error) {
    core.setFailed(`Secret scanner failed to run: ${error.message}`);
  }
}

/** Gets the list of files changed in the current PR via git diff. */
function getChangedFiles(context, repoRoot) {
  const base = process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : 'HEAD~1';
  try {
    execSync(`git fetch origin ${process.env.GITHUB_BASE_REF || ''} --depth=50`, { cwd: repoRoot, stdio: 'ignore' });
  } catch (e) {
    // best-effort; fall back to whatever refs are already available locally
  }
  try {
    const output = execSync(`git diff --name-only --diff-filter=ACMR ${base}...HEAD`, {
      cwd: repoRoot,
      encoding: 'utf8',
    });
    return output.split('\n').map((l) => l.trim()).filter(Boolean);
  } catch (e) {
    core.warning(`Could not compute git diff (${e.message}); falling back to full repo scan.`);
    return [];
  }
}

function printSummary(findings) {
  core.info('=== Secret Scan Findings ===');
  for (const f of findings) {
    core.info(`[${f.severity.toUpperCase()}] ${f.file}:${f.line} — ${f.type} (${f.match})`);
  }
}

async function postOrUpdatePRComment(context, token, findings) {
  const octokit = github.getOctokit(token);
  const { owner, repo } = context.repo;
  const prNumber = context.payload.pull_request?.number;
  if (!prNumber) return;

  const body = buildCommentBody(findings);

  const { data: comments } = await octokit.rest.issues.listComments({
    owner,
    repo,
    issue_number: prNumber,
  });
  const existing = comments.find((c) => c.body?.includes(COMMENT_MARKER));

  if (existing) {
    await octokit.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existing.id,
      body,
    });
  } else {
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: prNumber,
      body,
    });
  }
}

function buildCommentBody(findings) {
  if (findings.length === 0) {
    return `${COMMENT_MARKER}\n### 🔒 Secret Scan: Passed\nNo potential secrets found in this PR.`;
  }

  const rows = findings
    .map((f) => `| ${f.severity} | \`${f.file}\` | ${f.line} | ${f.type} | \`${f.match}\` |`)
    .join('\n');

  return `${COMMENT_MARKER}
### 🔒 Secret Scan: ${findings.length} potential secret(s) found

| Severity | File | Line | Type | Match (redacted) |
|---|---|---|---|---|
${rows}

**If these are real secrets:** rotate them immediately and remove them from the code (and git history if already pushed).
**If these are false positives:** add them to \`.secretscan.yml\` under \`ignore.strings\` or \`ignore.paths\`.`;
}

run();

module.exports = { run, buildCommentBody, getChangedFiles };
