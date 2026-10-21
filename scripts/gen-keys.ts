import { mkdirSync, writeFileSync } from 'node:fs';
import { generateKeyPair } from '../src/feed/sign.js';
const out = process.argv[2] ?? 'keys';
mkdirSync(out, { recursive: true });
for (const name of ['active', 'standby']) {
  const k = generateKeyPair();
  writeFileSync(`${out}/${name}.private.pem`, k.privateKeyPem, { mode: 0o600 });
  writeFileSync(`${out}/${name}.public.pem`, k.publicKeyPem);
  console.log(`${name}: key id ${k.keyId}, public key written to ${out}/${name}.public.pem (paste into src/client/keys.ts)`);
}
