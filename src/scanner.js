const fs = require('fs');
const path = require('path');
const { PATTERNS } = require('./patterns');
const { findHighEntropyStrings } = require('./entropy');

// Files/extensions we never want to scan (binary, lockfiles, vendored code)
const DEFAULT_IGNORE_PATHS = [
  'node_modules/',
  '.git/',
  'dist/',
  'build/',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
];

const DEFAULT_IGNORE_EXTENSIONS = [
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2',
  '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz', '.lock', '.min.js', '.map',
];

/**
 * Loads and parses a .secretscan.yml config, if present.
 * Supports a minimal YAML-ish subset (no external YAML dep needed):
 *   ignore:
 *     paths:
 *       - "test/fixtures/**"
 *     strings:
 *       - "EXAMPLE_KEY_NOT_REAL"
 */
function loadConfig(repoRoot) {
  const configPath = path.join(repoRoot, '.secretscan.yml');
  const config = { ignorePaths: [], ignoreStrings: [] };

  if (!fs.existsSync(configPath)) return config;

  const raw = fs.readFileSync(configPath, 'utf8');
  const lines = raw.split('\n');
  let section = null; // 'paths' | 'strings' | null

  for (const rawLine of lines) {
    const line = rawLine.replace(/#.*$/, '').trimEnd();
    if (!line.trim()) continue;

    if (/^\s*paths:\s*$/.test(line)) {
      section = 'paths';
      continue;
    }
    if (/^\s*strings:\s*$/.test(line)) {
      section = 'strings';
      continue;
    }
    if (/^ignore:\s*$/.test(line)) {
      continue;
    }

    const itemMatch = line.match(/^\s*-\s*["']?(.+?)["']?\s*$/);
    if (itemMatch && section) {
      const value = itemMatch[1];
      if (section === 'paths') config.ignorePaths.push(value);
      if (section === 'strings') config.ignoreStrings.push(value);
    }
  }

  return config;
}

/** Very small glob-ish matcher: supports '*' wildcard and simple prefix paths. */
function pathIsIgnored(filePath, ignorePaths) {
  const normalized = filePath.replace(/\\/g, '/');

  for (const p of DEFAULT_IGNORE_PATHS) {
    if (normalized.includes(p)) return true;
  }
  const ext = path.extname(normalized).toLowerCase();
  if (DEFAULT_IGNORE_EXTENSIONS.includes(ext)) return true;

  for (const pattern of ignorePaths) {
    const regexStr = '^' + pattern
      .split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$';
    if (new RegExp(regexStr).test(normalized) || normalized.includes(pattern.replace(/\*/g, ''))) {
      return true;
    }
  }
  return false;
}

/**
 * Scans a single file's content for secrets.
 * Returns an array of findings: { file, line, column, type, match, severity }
 */
function scanContent(filePath, content, config = { ignoreStrings: [] }) {
  const findings = [];
  const lines = content.split('\n');

  lines.forEach((lineText, idx) => {
    const lineNumber = idx + 1;

    // 1. Known pattern matching
    for (const pattern of PATTERNS) {
      pattern.regex.lastIndex = 0; // reset global regex state
      let m;
      while ((m = pattern.regex.exec(lineText)) !== null) {
        const matchedValue = pattern.captureValue && m[1] ? m[1] : m[0];
        if (config.ignoreStrings.includes(matchedValue)) continue;

        findings.push({
          file: filePath,
          line: lineNumber,
          column: m.index + 1,
          type: pattern.name,
          typeId: pattern.id,
          match: redact(matchedValue),
          severity: 'high',
          source: 'pattern',
        });

        if (!pattern.regex.global) break;
      }
    }

    // 2. Entropy-based detection (skip lines already caught by a pattern,
    //    and skip obvious comments/imports to cut down on noise)
    if (!/^\s*(\/\/|#|\*|import |require\()/.test(lineText)) {
      const hits = findHighEntropyStrings(lineText);
      for (const hit of hits) {
        if (config.ignoreStrings.includes(hit.token)) continue;

        findings.push({
          file: filePath,
          line: lineNumber,
          column: hit.index + 1,
          type: `High-entropy ${hit.kind} string`,
          typeId: 'high-entropy',
          match: redact(hit.token),
          severity: 'medium',
          source: 'entropy',
          entropy: Number(hit.entropy.toFixed(2)),
        });
      }
    }
  });

  return findings;
}

/** Redacts a secret for safe display: keeps first/last 3 chars only. */
function redact(value) {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 3)}${'*'.repeat(Math.min(value.length - 6, 20))}${value.slice(-3)}`;
}

/** Recursively walks a directory, returning file paths (respecting ignore rules). */
function walkFiles(dir, repoRoot, config, out = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(repoRoot, fullPath);

    if (pathIsIgnored(relPath, config.ignorePaths)) continue;

    if (entry.isDirectory()) {
      walkFiles(fullPath, repoRoot, config, out);
    } else if (entry.isFile()) {
      out.push(fullPath);
    }
  }
  return out;
}

/**
 * Scans a specific list of files (used for PR diffs) or an entire directory
 * (used for full-repo scans) and returns all findings.
 */
function scanFiles(filePaths, repoRoot, config) {
  const findings = [];
  for (const filePath of filePaths) {
    const relPath = path.relative(repoRoot, filePath);
    if (pathIsIgnored(relPath, config.ignorePaths)) continue;
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) continue;

    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch (e) {
      continue; // likely binary or unreadable
    }
    findings.push(...scanContent(relPath, content, config));
  }
  return findings;
}

function scanRepo(repoRoot, config) {
  const files = walkFiles(repoRoot, repoRoot, config);
  return scanFiles(files, repoRoot, config);
}

module.exports = {
  loadConfig,
  scanContent,
  scanFiles,
  scanRepo,
  walkFiles,
  redact,
  pathIsIgnored,
};
