// UNLEAK Core Deterministic Scrubber & WebCrypto AES-256-GCM Engine
// Runs identically in Browser (window.crypto.subtle) and Node.js 18+ (globalThis.crypto.subtle)

export const SECRET_PATTERNS = [
  {
    type: 'OPENAI_API_KEY',
    label: 'OpenAI Secret Key',
    severity: 'critical',
    regex: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}\b/g
  },
  {
    type: 'STRIPE_SECRET_KEY',
    label: 'Stripe Live Secret Key',
    severity: 'critical',
    regex: /\b(?:sk_live_|rk_live_|whsec_)[A-Za-z0-9]{14,}\b/g
  },
  {
    type: 'ANTHROPIC_API_KEY',
    label: 'Anthropic API Key',
    severity: 'critical',
    regex: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g
  },
  {
    type: 'POSTGRES_URI',
    label: 'PostgreSQL Connection URI',
    severity: 'critical',
    regex: /\bpostgres(?:ql)?:\/\/[^\s"'<>]+/gi
  },
  {
    type: 'REDIS_URI',
    label: 'Redis Connection URI',
    severity: 'high',
    regex: /\bredis(?:s)?:\/\/[^\s"'<>]+/gi
  },
  {
    type: 'MONGODB_URI',
    label: 'MongoDB Connection String',
    severity: 'critical',
    regex: /\bmongodb(?:\+srv)?:\/\/[^\s"'<>]+/gi
  },
  {
    type: 'AWS_ACCESS_KEY',
    label: 'AWS Access Key ID',
    severity: 'critical',
    regex: /\bAKIA[0-9A-Z]{16}\b/g
  },
  {
    type: 'GITHUB_TOKEN',
    label: 'GitHub Personal Access Token',
    severity: 'high',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g
  },
  {
    type: 'SLACK_TOKEN',
    label: 'Slack Bot / Webhook Token',
    severity: 'high',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g
  },
  {
    type: 'ENV_ASSIGNMENT',
    label: 'Inline Environment Secret',
    severity: 'high',
    regex: /\b([A-Z][A-Z0-9_]{2,}_(?:KEY|SECRET|TOKEN|PASSWORD|PASS|PRIVATE_KEY|WEBHOOK))\s*=\s*(?:"([^"\r\n]{6,})"|'([^'\r\n]{6,})'|([^\s"'`#]{6,}))/g
  }
];

const URI_TRAILING_PUNCTUATION = /[.,;:!?)]+$/;

/**
 * Scans a messy chat message and extracts all secret spans deterministically.
 */
export function detectSecretsInMessage(rawText) {
  if (typeof rawText !== 'string' || !rawText.trim()) return [];

  const candidates = [];

  for (const rule of SECRET_PATTERNS) {
    const regex = new RegExp(rule.regex.source, rule.regex.flags);
    let match;
    while ((match = regex.exec(rawText)) !== null) {
      if (rule.type === 'ENV_ASSIGNMENT') {
        const keyName = match[1];
        const secretValue = match[2] || match[3] || match[4];
        if (!secretValue) continue;
        const valueOffset = match.index + match[0].indexOf(secretValue);
        candidates.push({
          type: keyName,
          label: `${keyName} (Env Secret)`,
          severity: rule.severity,
          value: secretValue,
          start: valueOffset,
          end: valueOffset + secretValue.length
        });
      } else {
        let val = match[0];
        let start = match.index;
        if (rule.type.includes('URI')) {
          val = val.replace(URI_TRAILING_PUNCTUATION, '');
        }
        candidates.push({
          type: rule.type,
          label: rule.label,
          severity: rule.severity,
          value: val,
          start: start,
          end: start + val.length
        });
      }
    }
  }

  // Sort by start index, longest match first on tie, and deduplicate overlapping spans
  candidates.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));

  const deduplicated = [];
  let cursor = -1;
  for (const item of candidates) {
    if (item.start >= cursor) {
      deduplicated.push({
        ...item,
        maskedPreview: maskSecretValue(item.value)
      });
      cursor = item.end;
    }
  }

  return deduplicated;
}

export function maskSecretValue(val) {
  if (!val || val.length <= 10) return '••••••••';
  return `${val.slice(0, 6)}••••${val.slice(-4)}`;
}

// Base64URL helpers
export function bytesToBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 = typeof btoa === 'function'
    ? btoa(binary)
    : Buffer.from(bytes).toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64url.length + 3) % 4);
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

/**
 * Encrypts a single secret using WebCrypto AES-256-GCM.
 * Returns { ciphertext, iv, keyFragment } where keyFragment NEVER goes to the server.
 */
export async function encryptSecretGCM(plaintext) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto subtle API unavailable');

  const rawKey = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rawKey);

  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);

  const cryptoKey = await subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const encoded = new TextEncoder().encode(plaintext);
  const encryptedBuffer = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    encoded
  );

  return {
    ciphertext: bytesToBase64Url(new Uint8Array(encryptedBuffer)),
    iv: bytesToBase64Url(iv),
    keyFragment: bytesToBase64Url(rawKey)
  };
}

/**
 * Decrypts ciphertext using the keyFragment from the URL #hash.
 */
export async function decryptSecretGCM(ciphertextB64, ivB64, keyFragmentB64) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto subtle API unavailable');

  const rawKey = base64UrlToBytes(keyFragmentB64);
  const iv = base64UrlToBytes(ivB64);
  const ciphertext = base64UrlToBytes(ciphertextB64);

  const cryptoKey = await subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const decryptedBuffer = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertext
  );

  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * Validates that an AI rotation advisor payload contains ONLY variable names/types
 * and zero actual secret values.
 */
export function validateZeroTrustAiPayload(keyTypes) {
  if (!Array.isArray(keyTypes) || keyTypes.length === 0) {
    return { valid: false, reason: 'keyTypes must be a non-empty array of variable type names.' };
  }
  for (const item of keyTypes) {
    if (typeof item !== 'string' || item.length > 64) {
      return { valid: false, reason: 'Invalid key identifier format.' };
    }
    // Refuse if someone tries to pass an actual secret value into the AI advisor
    if (detectSecretsInMessage(item).length > 0 || item.includes('://') || /^sk[-_]/.test(item)) {
      return {
        valid: false,
        reason: 'ZERO_TRUST_VIOLATION: Raw secret values are strictly banned from AI payloads.'
      };
    }
  }
  return { valid: true };
}
