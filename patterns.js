/**
 * Known secret patterns, keyed by a short id.
 * Each entry: { name, regex, description }
 *
 * These patterns match well-known key/token formats. Keep regexes
 * reasonably specific to avoid false positives — generic high-entropy
 * strings that don't match any of these are caught separately by
 * entropy.js instead of being crammed into a giant fuzzy regex here.
 */

const PATTERNS = [
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    regex: /(?:aws)?_?secret_?(?:access)?_?key['"]?\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi,
  },
  {
    id: 'github-pat',
    name: 'GitHub Personal Access Token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
  },
  {
    id: 'github-fine-grained-pat',
    name: 'GitHub Fine-Grained PAT',
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
  },
  {
    id: 'gitlab-pat',
    name: 'GitLab Personal Access Token',
    regex: /\bglpat-[A-Za-z0-9\-_]{20}\b/g,
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,72}\b/g,
  },
  {
    id: 'slack-webhook',
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8,}\/B[A-Za-z0-9_]{8,}\/[A-Za-z0-9_]{24}/g,
  },
  {
    id: 'stripe-live-key',
    name: 'Stripe Live Secret Key',
    regex: /\bsk_live_[A-Za-z0-9]{24,247}\b/g,
  },
  {
    id: 'stripe-restricted-key',
    name: 'Stripe Restricted Key',
    regex: /\brk_live_[A-Za-z0-9]{24,247}\b/g,
  },
  {
    id: 'google-api-key',
    name: 'Google API Key',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    id: 'google-oauth-client-secret',
    name: 'Google OAuth Client Secret',
    regex: /\bGOCSPX-[A-Za-z0-9\-_]{28}\b/g,
  },
  {
    id: 'firebase-cloud-messaging',
    name: 'Firebase Cloud Messaging Key',
    regex: /\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b/g,
  },
  {
    id: 'jwt',
    name: 'JSON Web Token',
    regex: /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
  },
  {
    id: 'private-key-block',
    name: 'Private Key Block',
    regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----/g,
  },
  {
    id: 'npm-token',
    name: 'NPM Access Token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
  },
  {
    id: 'twilio-api-key',
    name: 'Twilio API Key',
    regex: /\bSK[0-9a-fA-F]{32}\b/g,
  },
  {
    id: 'sendgrid-api-key',
    name: 'SendGrid API Key',
    regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g,
  },
  {
    id: 'mailgun-api-key',
    name: 'Mailgun API Key',
    regex: /\bkey-[0-9a-f]{32}\b/g,
  },
  {
    id: 'generic-db-conn-string',
    name: 'Database Connection String with Credentials',
    regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[A-Za-z0-9_.-]+:[^@\s'"]{3,}@[A-Za-z0-9_.-]+/gi,
  },
  {
    id: 'generic-api-key-assignment',
    name: 'Generic API Key/Secret Assignment',
    // Catches things like: api_key = "abc123...", secret: 'xyz...'
    regex: /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-/+=]{16,})['"]/gi,
    // Group 1 holds the actual value; used for entropy cross-check by scanner.js
    captureValue: true,
  },
];

module.exports = { PATTERNS };
