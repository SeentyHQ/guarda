import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
export function keyIdOf(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex').slice(0, 16);
}
export function generateKeyPair(): { publicKeyPem: string; privateKeyPem: string; keyId: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return { publicKeyPem, privateKeyPem, keyId: keyIdOf(publicKeyPem) };
}
export function signBytes(bytes: Uint8Array, privateKeyPem: string): string {
  return sign(null, bytes, createPrivateKey(privateKeyPem)).toString('base64');
}
