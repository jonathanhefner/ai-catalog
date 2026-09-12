// Informative conformance harness, not a production verifier. Node.js >=22.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const vector = JSON.parse(readFileSync(new URL('../specification/test-vectors/entry-signature.json', import.meta.url)));
const context = 'ai-catalog-entry-signature-v1';
const now = Date.parse('2026-09-12T12:00:00Z');
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const pathCompare = (a, b) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const order = compare(a[i], b[i]);
    if (order) return order;
  }
  return a.length - b.length;
};

// RFC 8785 serialization for already-parsed I-JSON input. A production parser
// must additionally reject duplicate JSON object names before they are lost.
export function canonicalize(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw Error('Non-finite number');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw Error('Invalid Unicode');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort(compare).map(key =>
    `${canonicalize(key)}:${canonicalize(value[key])}`).join(',')}}`;
  throw Error('Not a JSON value');
}

function fields(document, paths) {
  if (!Array.isArray(paths) || paths.length === 0) throw Error('Empty paths');
  for (const path of paths) {
    if (!Array.isArray(path) || path.length === 0 || path.some(key => typeof key !== 'string')) throw Error('Invalid path');
    if (path[0] === 'signatures') throw Error('Self signature selection');
  }
  const sorted = [...paths].sort(pathCompare);
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i - 1].every((key, j) => sorted[i][j] === key)) throw Error('Overlapping paths');
  }
  return sorted.map(path => {
    let value = document;
    for (const key of path) {
      if (!object(value) || !own(value, key)) throw Error('Missing key or array traversal');
      value = value[key];
    }
    return [path, value];
  });
}

export function payload(document, signature, scope = context) {
  if (!['ai-catalog-entry-signature-v1', 'ai-catalog-host-signature-v1', 'ai-catalog-catalog-signature-v1'].includes(scope)) throw Error('Unknown context');
  if (!object(signature) || Object.keys(signature).some(key => !['paths', 'issuedAt', 'expiresAt', 'jws'].includes(key))) throw Error('Unknown signature field');
  return canonicalize({ context: scope, fields: fields(document, signature.paths),
    issuedAt: signature.issuedAt, ...(own(signature, 'expiresAt') ? { expiresAt: signature.expiresAt } : {}) });
}

function timestamp(value) {
  // Fixtures use ordinary RFC 3339 instants. Leap seconds require a fuller parser.
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) || !Number.isFinite(Date.parse(value))) throw Error('Invalid timestamp');
  return Date.parse(value);
}

export function check(document, signature, scope = context, at = now) {
  const encoded = payload(document, signature, scope);
  if (typeof signature.jws !== 'string') throw Error('Missing JWS');
  const parts = signature.jws.split('.');
  if (parts.length !== 3 || parts[1] !== '' || !parts[0] || !parts[2]) throw Error('Not detached compact JWS');
  const decode = text => {
    if (!/^[A-Za-z0-9_-]+$/.test(text)) throw Error('Invalid base64url');
    const bytes = Buffer.from(text, 'base64url');
    if (bytes.toString('base64url') !== text) throw Error('Noncanonical base64url');
    return bytes;
  };
  const header = JSON.parse(decode(parts[0]).toString('utf8'));
  if (header.alg !== 'ES256' || own(header, 'b64') || own(header, 'crit')) throw Error('Unsupported JWS header');
  if (header.kid !== vector.kid) throw Error('Unexpected fixture key');
  const input = Buffer.from(`${parts[0]}.${Buffer.from(encoded).toString('base64url')}`);
  if (!verify('sha256', input, { key: createPublicKey({ key: vector.publicKey, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, decode(parts[2]))) throw Error('Invalid signature');
  const issued = timestamp(signature.issuedAt);
  const expires = own(signature, 'expiresAt') ? timestamp(signature.expiresAt) : undefined;
  if (expires !== undefined && expires <= issued) throw Error('Expiration must follow issuance');
  if (issued > at) throw Error('Not yet issued');
  if (expires !== undefined && expires <= at) throw Error('Expired');
  return encoded;
}

function releaseCoverage(entry, signature) {
  const selected = name => signature.paths.some(path => path.length === 1 && path[0] === name);
  for (const name of ['identifier', 'type', 'digest', ...(own(entry, 'version') ? ['version'] : [])]) {
    if (!own(entry, name) || !selected(name)) throw Error(`Missing release coverage: ${name}`);
  }
}

const copy = value => structuredClone(value);
test('fixed ES256 golden payload and signature', () => {
  assert.equal(check(vector.entry, vector.signature), vector.canonicalPayload);
  releaseCoverage(vector.entry, vector.signature);
});
test('path list and object property order do not matter', () => {
  const sig = copy(vector.signature); sig.paths.reverse();
  const entry = Object.fromEntries(Object.entries(vector.entry).reverse());
  entry.signatures = [sig]; // The containing signature array is not selected.
  assert.equal(check(entry, sig), vector.canonicalPayload);
  entry.signatures.push(copy(sig));
  assert.equal(check(entry, sig), vector.canonicalPayload);
});
test('segment ordering uses UTF-16 code units and object-key traversal', () => {
  const entry = { '\uE000': 1, '\u{10000}': 2, '': 3, object: { '0': 4 } };
  const sig = { ...vector.signature, paths: [['\uE000'], ['object', '0'], ['\u{10000}'], ['']] };
  assert.deepEqual(JSON.parse(payload(entry, sig)).fields.map(([path]) => path), [[''], ['object', '0'], ['\u{10000}'], ['\uE000']]);
});
test('reject non-detached compact JWS and unsupported protected parameters', () => {
  const [header, , signature] = vector.signature.jws.split('.');
  for (const jws of [`${header}.e30.${signature}`, `${header}.${signature}`, `${header}...${signature}`]) {
    assert.throws(() => check(vector.entry, { ...vector.signature, jws }), /Not detached/);
  }
  for (const extra of [{ alg: 'HS256' }, { b64: false }, { b64: true }, { crit: ['unknown'] }]) {
    const changed = Buffer.from(JSON.stringify({ alg: 'ES256', kid: vector.kid, ...extra })).toString('base64url');
    assert.throws(() => check(vector.entry, { ...vector.signature, jws: `${changed}..${signature}` }), /Unsupported JWS header/);
  }
});
test('same value at another path cannot inherit endorsement', () => {
  const entry = copy(vector.entry); entry.alias = entry.identifier;
  const sig = copy(vector.signature); sig.paths[sig.paths.findIndex(p => p[0] === 'identifier')] = ['alias'];
  assert.throws(() => check(entry, sig), /Invalid signature/);
});
test('identity-map key rename breaks signature; second contributor does not', () => {
  const entry = copy(vector.entry);
  entry.trustManifests['did:web:assessor.example'] = { attestations: [{ type: 'SOC2-Type2', uri: 'https://assessor.example/report.pdf' }] };
  check(entry, vector.signature);
  const signer = 'did:web:publisher.example';
  entry.trustManifests['did:web:renamed.example'] = entry.trustManifests[signer];
  delete entry.trustManifests[signer];
  assert.throws(() => check(entry, vector.signature), /Missing key/);
});
test('whole selected manifest includes its arrays, null values and nested signatures', () => {
  for (const mutate of [
    manifest => manifest.provenance.reverse(),
    manifest => manifest.attestations.push({ type: 'Other', uri: 'https://example.com/other' }),
    manifest => manifest.extra = true,
    manifest => manifest.extensions['https://example.com/opaque'].signatures.push({ example: 'new nested signature' }),
  ]) {
    const entry = copy(vector.entry); mutate(entry.trustManifests['did:web:publisher.example']);
    assert.throws(() => check(entry, vector.signature), /Invalid signature/);
  }
});
test('context and timestamp mutations fail cryptographic verification; expiration is enforced', () => {
  for (const scope of ['ai-catalog-host-signature-v1', 'ai-catalog-catalog-signature-v1']) assert.throws(() => check(vector.entry, vector.signature, scope), /Invalid signature/);
  for (const name of ['issuedAt', 'expiresAt']) {
    const sig = copy(vector.signature); sig[name] = '2027-01-01T00:00:00Z';
    assert.throws(() => check(vector.entry, sig), /Invalid signature/);
  }
  assert.throws(() => check(vector.entry, vector.signature, context, Date.parse(vector.signature.expiresAt)), /Expired/);
  assert.throws(() => check(vector.entry, vector.signature, context, 0), /Not yet issued/);
});
test('reject invalid selections and unknown outer metadata', () => {
  for (const paths of [[], [[]], [['missing']], [['signatures']], [['type'], ['type']],
    [['trustManifests'], ['trustManifests', 'did:web:publisher.example']],
    [['trustManifests', 'did:web:publisher.example', 'provenance', '0']], [['type', 0]]]) {
    assert.throws(() => payload(vector.entry, { ...vector.signature, paths }));
  }
  assert.throws(() => payload(vector.entry, { ...vector.signature, extra: true }), /Unknown signature field/);
  assert.throws(() => payload({}, { ...vector.signature, paths: [['toString']] }), /Missing key/);
  assert.doesNotThrow(() => payload({ nullable: null }, { ...vector.signature, paths: [['nullable']] }));
});
test('mandatory release coverage and unsigned inserted version', () => {
  for (const name of ['identifier', 'type', 'digest', 'version']) {
    assert.throws(() => releaseCoverage(vector.entry, { ...vector.signature, paths: vector.signature.paths.filter(p => p[0] !== name) }), /Missing release coverage/);
  }
  const entry = copy(vector.entry); delete entry.version;
  const sig = copy(vector.unversionedSignature);
  check(entry, sig); releaseCoverage(entry, sig);
  entry.version = '2.0.0';
  check(entry, sig); // Cryptography alone cannot detect addition of an unselected field.
  assert.throws(() => releaseCoverage(entry, sig), /Missing release coverage: version/);
});
test('artifact digest binds exact bytes independently of entry JWS', () => {
  const digest = data => `sha256:${createHash('sha256').update(data).digest('hex')}`;
  assert.equal(digest(vector.artifactUtf8), vector.entry.digest);
  assert.notEqual(digest(`${vector.artifactUtf8}\n`), vector.entry.digest);
});
