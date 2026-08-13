/**
 * Shannon entropy detection.
 *
 * Known secret patterns only catch formats we already know about.
 * Entropy detection catches the rest: random-looking, high-entropy
 * strings that are likely to be secrets even if they don't match
 * any known vendor format.
 */

const HEX_CHARS = '0123456789abcdefABCDEF';
const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

/** Standard Shannon entropy in bits per character. */
function shannonEntropy(str) {
  if (!str.length) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Finds candidate high-entropy substrings (hex-like or base64-like tokens)
 * inside a line of code, e.g. values assigned to variables or embedded in
 * strings, and returns any that exceed sensible entropy thresholds.
 *
 * Thresholds are tuned conservatively to avoid flagging things like UUIDs,
 * hashes of short content, or normal English words:
 *   - hex strings: need entropy > 3.0 bits/char AND length >= 20
 *   - base64 strings: need entropy > 4.5 bits/char AND length >= 20
 */
function findHighEntropyStrings(line, { minLength = 20 } = {}) {
  const findings = [];

  // Extract quoted string literals and bare tokens that look like secrets
  const tokenRegex = /['"`]?([A-Za-z0-9+/=_-]{20,})['"`]?/g;
  let match;
  const seen = new Set();

  while ((match = tokenRegex.exec(line)) !== null) {
    const token = match[1];
    if (token.length < minLength || seen.has(token)) continue;
    seen.add(token);

    const isHex = [...token].every((c) => HEX_CHARS.includes(c));
    const isB64ish = [...token].every((c) => B64_CHARS.includes(c));

    if (isHex && token.length >= 32) {
      const ent = shannonEntropy(token);
      if (ent > 3.0) {
        findings.push({ token, entropy: ent, kind: 'hex', index: match.index });
      }
    } else if (isB64ish) {
      const ent = shannonEntropy(token);
      if (ent > 4.5) {
        findings.push({ token, entropy: ent, kind: 'base64', index: match.index });
      }
    }
  }

  return findings;
}

module.exports = { shannonEntropy, findHighEntropyStrings };
