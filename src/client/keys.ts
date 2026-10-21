/**
 * Feed signing keys (public, Ed25519 SPKI). The feed manifest must verify against one of these.
 * Rotation: publish the next key as standby first, sign with it after every supported CLI ships it,
 * then retire the old one. Generate a pair with `npm run gen-keys`; the private half never enters the repo.
 */
export const PINNED_PUBLIC_KEYS: string[] = [
  // active
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAQalDU4dsubAW4f22MMgBIk4/t3WefY/wRwsBwlX1ee0=\n-----END PUBLIC KEY-----\n",
  // standby
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAaBvaSGRo4xndt+TZ5N8997BP09Y5vSvzKLx8kVBKZe4=\n-----END PUBLIC KEY-----\n",
];
export const DEFAULT_FEED_URL = 'https://feed.seenty.com/guarda/v1';
