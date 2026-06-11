// Exercise Node's Web Crypto (`crypto.subtle` / SubtleCrypto) over the
// FIPS-approved algorithm set, in the FIPS-provider image. Run as part of
// ci/fips-compliance-check.sh, after the OpenSSL FIPS module has been
// self-tested and shown to enforce approved-only at the crypto layer.
//
// These are exactly the CNSA-2.0-relevant approved primitives talkrypt itself
// uses the validated families of (SHA-384, AES-256-GCM, ECDSA P-384). Each must
// succeed; the run exits non-zero on any failure.
import crypto from 'node:crypto';

const subtle = globalThis.crypto.subtle;
const fail = (m) => { console.error('    ✗ FAIL:', m); process.exit(1); };
const ok = (m) => console.log('    ✓', m);

console.log('    node', process.version, '| openssl', process.versions.openssl,
            '| crypto.getFips()=', (() => { try { return crypto.getFips(); } catch { return 'n/a'; } })());

const data = new TextEncoder().encode('talkrypt FIPS SubtleCrypto check');

const dig = await subtle.digest('SHA-384', data);
if (dig.byteLength !== 48) fail('SHA-384 digest wrong length');
ok('subtle.digest SHA-384 (FIPS 180-4)');

const aesKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, data);
const pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct));
if (Buffer.compare(Buffer.from(pt), Buffer.from(data)) !== 0) fail('AES-256-GCM roundtrip mismatch');
ok('subtle AES-256-GCM encrypt/decrypt (FIPS 197 / SP 800-38D)');

const ec = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, ['sign', 'verify']);
const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, ec.privateKey, data);
if (!(await subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, ec.publicKey, sig, data)))
  fail('ECDSA P-384 verify failed');
ok('subtle ECDSA P-384 sign/verify (FIPS 186-5)');

console.log('    SubtleCrypto approved-algorithm set: OK');
