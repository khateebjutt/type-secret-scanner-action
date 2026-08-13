const assert = require('assert');
const { scanContent, redact, pathIsIgnored } = require('../src/scanner');
const { shannonEntropy, findHighEntropyStrings } = require('../src/entropy');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${err.message}`);
    failed++;
  }
}

console.log('\nPattern detection:');

test('detects AWS access key', () => {
  const content = `const key = "AKIAIOSFODNN7EXAMPLE";`;
  const findings = scanContent('test.js', content, { ignoreStrings: [] });
  assert.ok(findings.some((f) => f.typeId === 'aws-access-key-id'));
});

test('detects GitHub PAT', () => {
  const content = `TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz`;
  const findings = scanContent('.env', content, { ignoreStrings: [] });
  assert.ok(findings.some((f) => f.typeId === 'github-pat'));
});

test('detects Slack webhook URL', () => {
  const content = `webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"`;
  const findings = scanContent('config.js', content, { ignoreStrings: [] });
  assert.ok(findings.some((f) => f.typeId === 'slack-webhook'));
});

test('detects Stripe live secret key', () => {
  const content = `stripe.apiKey = 'sk_live_4eC39HqLyjWDarjtT1zdp7dcAAAAAAAAAAAA';`;
  const findings = scanContent('payments.js', content, { ignoreStrings: [] });
  assert.ok(findings.some((f) => f.typeId === 'stripe-live-key'));
});

test('detects private key block', () => {
  const content = `-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...`;
  const findings = scanContent('id_rsa', content, { ignoreStrings: [] });
  assert.ok(findings.some((f) => f.typeId === 'private-key-block'));
});

test('detects generic api_key assignment', () => {
  const content = `api_key: "sadf923jf0923jfa0923fjaslkdfj230"`;
  const findings = scanContent('settings.yml', content, { ignoreStrings: [] });
  assert.ok(findings.some((f) => f.typeId === 'generic-api-key-assignment'));
});

test('detects DB connection string with credentials', () => {
  const content = `DATABASE_URL=postgres://admin:sup3rSecr3t@db.example.com:5432/prod`;
  const findings = scanContent('.env', content, { ignoreStrings: [] });
  assert.ok(findings.some((f) => f.typeId === 'generic-db-conn-string'));
});

test('does not flag normal code', () => {
  const content = `function add(a, b) {\n  return a + b;\n}\nconst name = "khateeb";`;
  const findings = scanContent('math.js', content, { ignoreStrings: [] });
  assert.strictEqual(findings.length, 0);
});

test('respects ignoreStrings config', () => {
  const content = `const key = "AKIAIOSFODNN7EXAMPLE";`;
  const findings = scanContent('test.js', content, { ignoreStrings: ['AKIAIOSFODNN7EXAMPLE'] });
  assert.strictEqual(findings.length, 0);
});

console.log('\nEntropy detection:');

test('shannon entropy of repetitive string is low', () => {
  const ent = shannonEntropy('aaaaaaaaaaaaaaaaaaaa');
  assert.ok(ent < 1);
});

test('shannon entropy of random string is high', () => {
  const ent = shannonEntropy('aX9$kQ2!zP7mW4nR8vT1');
  assert.ok(ent > 3.5);
});

test('finds high-entropy base64-like token in line', () => {
  const line = `const secret = "aB3xZ9qL2mP7vN4wR8tY6uJ1cF5dK0hG";`;
  const hits = findHighEntropyStrings(line);
  assert.ok(hits.length > 0);
});

test('does not flag short common words', () => {
  const line = `const greeting = "hello world how are you today";`;
  const hits = findHighEntropyStrings(line);
  assert.strictEqual(hits.length, 0);
});

console.log('\nRedaction:');

test('redacts long secrets, keeping only first/last 3 chars', () => {
  const r = redact('AKIAIOSFODNN7EXAMPLE');
  assert.ok(r.startsWith('AKI'));
  assert.ok(r.endsWith('PLE'));
  assert.ok(r.includes('*'));
});

test('fully redacts very short secrets', () => {
  const r = redact('abcd1234');
  assert.strictEqual(r, '*'.repeat(8));
});

console.log('\nPath ignoring:');

test('ignores node_modules by default', () => {
  assert.strictEqual(pathIsIgnored('node_modules/foo/index.js', []), true);
});

test('ignores files by custom glob pattern', () => {
  assert.strictEqual(pathIsIgnored('test/fixtures/fake-keys.js', ['test/fixtures/**']), true);
});

test('does not ignore normal source files', () => {
  assert.strictEqual(pathIsIgnored('src/index.js', []), false);
});

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
