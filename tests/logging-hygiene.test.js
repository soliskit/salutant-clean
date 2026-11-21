// R13 logging and R10 clean public repo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, relative, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { makeWorld, honestSignIn, OWNER } from './helpers.js';

void test('logs hold no codes, proofs or addresses; subject lines carry no code', async () => {
  const w = await makeWorld();
  const r = await honestSignIn(w);
  const logText = JSON.stringify(w.logSink);
  assert.ok(!logText.includes(String(r.code)), 'no code in logs');
  assert.ok(!logText.includes(OWNER), 'no address in logs');
  assert.ok(!logText.includes(r.verified.proof), 'no proof in logs');
  for (const entry of w.logSink) {
    assert.deepEqual(Object.keys(entry).sort(), [
      'event',
      'outcome',
      'source',
      'time'
    ]);
  }
  for (const mail of w.mailer.outbox) {
    assert.equal(mail.subject, 'Your sign-in code');
    assert.ok(
      !mail.subject.includes(String(r.code)),
      'the code appears only in the body'
    );
  }
  // The store holds keyed hashes only.
  const dump = JSON.stringify([...w.store.records]);
  assert.ok(!dump.includes(String(r.code)) && !dump.includes(OWNER));
});

// R10: scan the working tree for secrets and personal details. The scan
// is also a test so it runs in any future CI.
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SKIP_DIRS = new Set(['.git', 'node_modules']);
const PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /AKIA[0-9A-Z]{16}/, // AWS access key id
  /xox[baprs]-[0-9A-Za-z-]{10,}/, // Slack tokens
  /sk_live_[0-9a-zA-Z]{10,}/, // Stripe live key
  /re_[0-9a-zA-Z]{20,}/, // Resend API key shape
  /\b[\w.+-]+@(?!example\.(test|com|org))[\w-]+\.[\w.]+\b/ // non-example addresses
];

/** @param {string} dir @returns {Generator<string, void, unknown>} */
function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

// R10 owner-approved public Git attribution exception, exactly three source
// lines in two guards. These hashes compare the visible, unchanged literals;
// they do not replace, encode or hide the identity in either guard. No path is
// skipped, and every non-address secret pattern still checks every byte.
const PUBLIC_ATTRIBUTION_LINES = [
  {
    path: '.credit-guard/publication_gate.py',
    lineSha256:
      '2dd9bf0adcd599745106dc6e879147437d07b549479225868f096f496bdbcdc2',
    addressSha256:
      '5f03883e1219e57df95da0cb3add100fc59bbe0c6ef568d354ea39f1bdb26d8d',
    count: 1
  },
  {
    path: '.credit-guard/strict_guard.py',
    lineSha256:
      '2dd9bf0adcd599745106dc6e879147437d07b549479225868f096f496bdbcdc2',
    addressSha256:
      '5f03883e1219e57df95da0cb3add100fc59bbe0c6ef568d354ea39f1bdb26d8d',
    count: 1
  },
  {
    path: '.credit-guard/strict_guard.py',
    lineSha256:
      '2c051a54df1e5b7d9c3ca17c586a4de263ce7bf9bfc07670981e7360ee21f0ba',
    addressSha256:
      '5f03883e1219e57df95da0cb3add100fc59bbe0c6ef568d354ea39f1bdb26d8d',
    count: 1
  }
];

/** @param {string} text */
function sha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

/**
 * @param {Map<string, string>} files
 * @param {boolean} requireAttribution
 */
function scanPublicFiles(files, requireAttribution = false) {
  const hits = [];
  const seen = PUBLIC_ATTRIBUTION_LINES.map(() => 0);
  for (const [file, text] of files) {
    for (const [patternIndex, pattern] of PATTERNS.entries()) {
      const globalPattern = new RegExp(pattern.source, 'g');
      for (const match of text.matchAll(globalPattern)) {
        const start = text.lastIndexOf('\n', match.index - 1) + 1;
        const end = text.indexOf('\n', match.index);
        const line = text.slice(start, end === -1 ? text.length : end);
        const permitted =
          patternIndex === PATTERNS.length - 1
            ? PUBLIC_ATTRIBUTION_LINES.findIndex(
                (rule) =>
                  rule.path === file &&
                  rule.lineSha256 === sha256(line) &&
                  rule.addressSha256 === sha256(match[0])
              )
            : -1;
        if (permitted === -1) hits.push(`${file}: ${String(pattern)}`);
        else seen[permitted] += 1;
      }
    }
  }
  for (const [index, rule] of PUBLIC_ATTRIBUTION_LINES.entries()) {
    if (
      seen[index] > rule.count ||
      (requireAttribution && seen[index] !== rule.count)
    ) {
      hits.push(`${rule.path}: public-attribution occurrence count differs`);
    }
  }
  return hits;
}

void test('the working tree holds no secrets or unapproved personal addresses', () => {
  const files = new Map(
    [...walk(ROOT)].map((file) => [
      relative(ROOT, file).split(sep).join('/'),
      readFileSync(file, 'utf8')
    ])
  );
  assert.deepEqual(scanPublicFiles(files, true), [], 'scan must be clean');
});

void test('R10 permits only the exact public attribution source lines', () => {
  const files = new Map(
    PUBLIC_ATTRIBUTION_LINES.map((rule) => [
      rule.path,
      readFileSync(join(ROOT, rule.path), 'utf8')
    ])
  );
  assert.deepEqual(scanPublicFiles(files, true), []);
  assert.ok(PATTERNS.length > 0, 'the address pattern is present');
  const addressPattern = PATTERNS[PATTERNS.length - 1];
  /** @param {string} path @param {string} text */
  const reject = (path, text) => {
    const candidate = new Map(files);
    candidate.set(path, text);
    assert.ok(scanPublicFiles(candidate, true).length > 0);
  };
  for (const rule of PUBLIC_ATTRIBUTION_LINES) {
    const source = files.get(rule.path);
    assert.ok(source !== undefined);
    const exactLine = source
      .split('\n')
      .find((line) => sha256(line) === rule.lineSha256);
    assert.ok(exactLine !== undefined);
    const address = addressPattern.exec(exactLine)?.[0];
    assert.ok(address !== undefined);
    reject('other.py', exactLine);
    reject('logs/build.txt', address);
    reject('dist/bundle.js', address);
    reject('dist/bundle.js.map', address);
    reject(rule.path, source + '\n' + exactLine + '\n');
    reject(rule.path, source.replace(exactLine, exactLine + ' '));
    reject(
      rule.path,
      source.replace(
        exactLine,
        exactLine.replace(address, 'different-' + address)
      )
    );
    reject(rule.path, source.replace(exactLine, ''));
    reject(rule.path, source + '\n' + address + '\n');
    // All non-address detectors still apply inside the two permitted files.
    for (const sample of [
      '-----BEGIN ' + 'RSA PRIVATE KEY-----',
      'AKIA' + 'A'.repeat(16),
      'xoxb-' + 'a'.repeat(10),
      'sk_live_' + 'a'.repeat(10),
      're_' + 'a'.repeat(20)
    ])
      reject(rule.path, source + '\n' + sample + '\n');
  }
});

void test('a logged event drops entries older than 14 days and keeps newer ones', async () => {
  const w = await makeWorld();
  const day = 24 * 3_600_000;
  w.service.log('challenge', 'accepted', 'old');
  w.advance(1 * day);
  w.service.log('challenge', 'accepted', 'recent');
  w.advance(14 * day - 1);
  // The first entry is now 15 days minus 1 ms old, the second is 14 days minus 1 ms old.
  w.service.log('verify', 'rejected', 'new');
  assert.deepEqual(
    w.logSink.map((e) => e.source),
    ['recent', 'new']
  );
  w.advance(2);
  w.service.log('verify', 'rejected', 'later');
  assert.deepEqual(
    w.logSink.map((e) => e.source),
    ['new', 'later']
  );
});

void test('an entry exactly 14 days old is kept', async () => {
  const w = await makeWorld();
  w.service.log('challenge', 'accepted', 'edge');
  w.advance(14 * 24 * 3_600_000);
  w.service.log('verify', 'rejected', 'now');
  assert.deepEqual(
    w.logSink.map((e) => e.source),
    ['edge', 'now']
  );
});
