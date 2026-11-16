import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { validateZeroTrustAiPayload } from './src/scrubber.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// In-memory atomic capsule store
export const capsuleStore = new Map();

const ROTATION_PLAYBOOKS = {
  STRIPE_SECRET_KEY: {
    priority: 1,
    title: 'Roll Stripe Secret Key & Scope to Restricted Key',
    window: 'Immediate (Financial Settlement Access)',
    cliCommand: 'stripe api_keys create --name "restricted-handoff" --live',
    steps: [
      'Open Stripe Dashboard → Developers → API Keys and create a Restricted Key (rk_live_) scoped only to required endpoints.',
      'Roll the shared sk_live_ key with a 24-hour expiration window once deployment is verified.',
      'Confirm webhook signing secrets (whsec_) are bound strictly to the target environment.'
    ]
  },
  POSTGRES_URI: {
    priority: 2,
    title: 'Rotate PostgreSQL Role Password & Enforce SSL',
    window: 'Within 2 hours of handoff',
    cliCommand: 'psql "$DATABASE_URL" -c "ALTER ROLE app_writer WITH PASSWORD \'new_scoped_secret\';"',
    steps: [
      'Replace superuser credentials with a least-privilege role (GRANT SELECT, INSERT, UPDATE ON TABLE ...).',
      'Append ?sslmode=require to the connection string and verify IP allowlist rules.',
      'Execute ALTER ROLE password rotation once migration or local setup completes.'
    ]
  },
  OPENAI_API_KEY: {
    priority: 3,
    title: 'Revoke Onboarding Key & Enforce Project Spend Cap',
    window: 'Within 4 hours of handoff',
    cliCommand: 'curl https://api.openai.com/v1/organization/projects/$PROJECT_ID/api_keys',
    steps: [
      'Use a dedicated Project Service Account key (sk-proj-...) instead of an organization owner key.',
      'Set a hard monthly spend limit in platform.openai.com → Limits.',
      'Revoke the temporary handoff key once loaded into the target secret manager.'
    ]
  },
  ANTHROPIC_API_KEY: {
    priority: 3,
    title: 'Rotate Anthropic Workspace Key',
    window: 'Within 4 hours of handoff',
    cliCommand: '# Console → Workspaces → API Keys → Create Scoped Key',
    steps: [
      'Isolate the key inside a dedicated Anthropic Workspace with a monthly token cap.',
      'Disable the temporary onboarding key after environment configuration.'
    ]
  },
  AWS_ACCESS_KEY: {
    priority: 1,
    title: 'Deactivate Static IAM Key & Switch to STS AssumeRole',
    window: 'Immediate (Cloud Infrastructure Access)',
    cliCommand: 'aws iam update-access-key --access-key-id AKIA... --status Inactive',
    steps: [
      'Inspect CloudTrail events for the shared AKIA access key ID.',
      'Deactivate the static IAM key and replace with short-lived OIDC or STS AssumeRole credentials.'
    ]
  },
  GITHUB_TOKEN: {
    priority: 2,
    title: 'Replace PAT with Fine-Grained Repository Token',
    window: 'Within 4 hours of handoff',
    cliCommand: 'gh auth status && gh token',
    steps: [
      'Scope Fine-Grained Personal Access Token to a single repository with 7-day expiration.',
      'Revoke the shared token under GitHub Settings → Developer Settings → Tokens.'
    ]
  },
  REDIS_URI: {
    priority: 3,
    title: 'Rotate Redis ACL User Password',
    window: 'Within 24 hours',
    cliCommand: 'redis-cli ACL SETUSER handoff_user on >new_pass ~cache:* +get +set -flushall',
    steps: [
      'Create a restricted Redis ACL user instead of sharing the default admin user.',
      'Remove the temporary ACL user once debugging concludes.'
    ]
  }
};

function buildRotationChecklist(keyTypes) {
  const uniqueTypes = [...new Set(keyTypes)];
  const items = uniqueTypes.map((type) => {
    const known = ROTATION_PLAYBOOKS[type];
    if (known) {
      return { type, ...known };
    }
    return {
      type,
      priority: 3,
      title: `Rotate & Scope ${type}`,
      window: 'After handoff completion',
      cliCommand: `# Rotate ${type} in provider dashboard and update .env`,
      steps: [
        `Move ${type} into your deployment secret store or local .env.local (never commit to git).`,
        `Generate a replacement credential and revoke this handoff token once verified.`
      ]
    };
  });

  items.sort((a, b) => a.priority - b.priority);
  return items;
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 256 * 1024) {
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(new Error('Invalid JSON payload'));
      }
    });
    req.on('error', reject);
  });
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png'
};

export async function handleRequest(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    if (pathname === '/favicon.ico') {
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 36"><rect x="12" y="2" width="12" height="9" rx="3.5" fill="#141413"/><rect x="12" y="25" width="12" height="9" rx="3.5" fill="#141413"/><rect x="2" y="12" width="9" height="12" rx="3.5" fill="#141413"/><rect x="25" y="12" width="9" height="12" rx="3.5" fill="#141413"/><circle cx="9.5" cy="9.5" r="2.5" fill="#141413"/><circle cx="26.5" cy="9.5" r="2.5" fill="#141413"/><circle cx="9.5" cy="26.5" r="2.5" fill="#141413"/><circle cx="26.5" cy="26.5" r="2.5" fill="#141413"/></svg>`;
      res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' });
      return res.end(svg);
    }

    // 1. Create Encrypted Capsule (POST /api/capsules)
    if (req.method === 'POST' && pathname === '/api/capsules') {
      try {
        const body = await readJsonBody(req);
        if (body.plaintext || body.keyFragment || body.rawSecret) {
          return sendJson(res, 400, {
            error: 'ZERO_KNOWLEDGE_VIOLATION',
            message: 'Server refuses plaintext or decryption key fragments. Encrypt in browser first.'
          });
        }
        const {
          ciphertext,
          iv,
          secretType = 'SECRET',
          label = 'Encrypted Secret',
          projectTag = 'Default Workspace',
          ttlMinutes = 60
        } = body;

        if (!ciphertext || !iv || typeof ciphertext !== 'string' || typeof iv !== 'string') {
          return sendJson(res, 400, {
            error: 'INVALID_CAPSULE',
            message: 'Both ciphertext and iv (base64url) are required.'
          });
        }

        const id = 'cap_' + crypto.randomBytes(6).toString('hex');
        const now = Date.now();
        const expiresAt = now + Math.min(Math.max(Number(ttlMinutes) || 60, 1), 10080) * 60 * 1000;

        capsuleStore.set(id, {
          id,
          secretType,
          label,
          projectTag: String(projectTag).slice(0, 48),
          ciphertext,
          iv,
          createdAt: new Date(now).toISOString(),
          expiresAt: new Date(expiresAt).toISOString(),
          expiresAtMs: expiresAt,
          crawlerHits: 0,
          status: 'LOCKED',
          burned: false,
          burnedAt: null,
          receiptHash: null
        });

        return sendJson(res, 201, {
          id,
          secretType,
          label,
          projectTag: String(projectTag).slice(0, 48),
          createdAt: new Date(now).toISOString(),
          expiresAt: new Date(expiresAt).toISOString(),
          status: 'LOCKED'
        });
      } catch (err) {
        return sendJson(res, 400, { error: 'BAD_REQUEST', message: err.message });
      }
    }

    // 2. List Workspace Capsules Metadata (GET /api/capsules)
    if (req.method === 'GET' && pathname === '/api/capsules') {
      const items = [];
      for (const cap of capsuleStore.values()) {
        if (Date.now() > cap.expiresAtMs && !cap.burned) {
          cap.ciphertext = null;
          cap.iv = null;
          cap.burned = true;
          cap.status = 'EXPIRED';
          cap.burnedAt = new Date().toISOString();
        }
        items.push({
          id: cap.id,
          secretType: cap.secretType,
          label: cap.label,
          projectTag: cap.projectTag,
          createdAt: cap.createdAt,
          expiresAt: cap.expiresAt,
          status: cap.status,
          burned: cap.burned,
          burnedAt: cap.burnedAt,
          crawlerHits: cap.crawlerHits,
          receiptHash: cap.receiptHash
        });
      }
      items.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return sendJson(res, 200, { capsules: items });
    }

    // 3. Single Capsule Status / Bot-Safe Preview (GET /api/capsules/:id)
    const capsuleMatch = pathname.match(/^\/api\/capsules\/([a-zA-Z0-9_]+)$/);
    if (req.method === 'GET' && capsuleMatch) {
      const id = capsuleMatch[1];
      const capsule = capsuleStore.get(id);

      if (!capsule) {
        return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Vault link not found.' });
      }

      if (Date.now() > capsule.expiresAtMs && !capsule.burned) {
        capsule.ciphertext = null;
        capsule.iv = null;
        capsule.burned = true;
        capsule.status = 'EXPIRED';
        capsule.burnedAt = new Date().toISOString();
      }

      if (capsule.burned) {
        return sendJson(res, 410, {
          id: capsule.id,
          status: capsule.status || 'BURNED',
          secretType: capsule.secretType,
          label: capsule.label,
          projectTag: capsule.projectTag,
          burnedAt: capsule.burnedAt,
          receiptHash: capsule.receiptHash,
          crawlerHits: capsule.crawlerHits,
          message:
            capsule.status === 'REVOKED'
              ? 'This vault link was revoked by the sender before it was opened.'
              : 'This credential was already revealed and permanently wiped from memory.'
        });
      }

      capsule.crawlerHits += 1;
      return sendJson(res, 200, {
        id: capsule.id,
        status: 'LOCKED',
        secretType: capsule.secretType,
        label: capsule.label,
        projectTag: capsule.projectTag,
        createdAt: capsule.createdAt,
        expiresAt: capsule.expiresAt,
        crawlerHits: capsule.crawlerHits,
        botPreviewSafe: true,
        message: 'Encrypted credential is locked and ready for one-time reveal.'
      });
    }

    // 4. Revoke Active Capsule (DELETE /api/capsules/:id)
    if (req.method === 'DELETE' && capsuleMatch) {
      const id = capsuleMatch[1];
      const capsule = capsuleStore.get(id);
      if (!capsule) {
        return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Capsule not found.' });
      }
      if (capsule.burned) {
        return sendJson(res, 400, { error: 'ALREADY_BURNED', message: 'Capsule is already destroyed.' });
      }
      const revokedAt = new Date().toISOString();
      const receiptHash = crypto
        .createHash('sha256')
        .update(`revoked:${capsule.id}:${revokedAt}`)
        .digest('hex')
        .slice(0, 20);

      capsule.ciphertext = null;
      capsule.iv = null;
      capsule.burned = true;
      capsule.status = 'REVOKED';
      capsule.burnedAt = revokedAt;
      capsule.receiptHash = `rev_${receiptHash}`;

      return sendJson(res, 200, {
        id: capsule.id,
        status: 'REVOKED',
        burnedAt: revokedAt,
        receiptHash: capsule.receiptHash
      });
    }

    // 5. Atomic Human Reveal & Burn (POST /api/capsules/:id/burn)
    const burnMatch = pathname.match(/^\/api\/capsules\/([a-zA-Z0-9_]+)\/burn$/);
    if (req.method === 'POST' && burnMatch) {
      const id = burnMatch[1];
      const capsule = capsuleStore.get(id);

      if (!capsule) {
        return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Capsule does not exist.' });
      }

      if (capsule.burned || !capsule.ciphertext || Date.now() > capsule.expiresAtMs) {
        if (Date.now() > capsule.expiresAtMs && !capsule.burned) {
          capsule.ciphertext = null;
          capsule.iv = null;
          capsule.burned = true;
          capsule.status = 'EXPIRED';
          capsule.burnedAt = new Date().toISOString();
        }
        return sendJson(res, 410, {
          id: capsule.id,
          status: capsule.status || 'BURNED',
          burnedAt: capsule.burnedAt,
          receiptHash: capsule.receiptHash,
          message:
            capsule.status === 'EXPIRED'
              ? '410 GONE: This vault link expired before it was opened.'
              : capsule.status === 'REVOKED'
              ? '410 GONE: This vault link was revoked by the sender.'
              : '410 GONE: Credential was already revealed and wiped from server memory.'
        });
      }

      const ciphertext = capsule.ciphertext;
      const iv = capsule.iv;
      const burnedAt = new Date().toISOString();
      const receiptHash = crypto
        .createHash('sha256')
        .update(`${capsule.id}:${burnedAt}:${capsule.secretType}`)
        .digest('hex')
        .slice(0, 20);

      capsule.ciphertext = null;
      capsule.iv = null;
      capsule.burned = true;
      capsule.status = 'BURNED';
      capsule.burnedAt = burnedAt;
      capsule.receiptHash = `burn_${receiptHash}`;

      return sendJson(res, 200, {
        id: capsule.id,
        status: 'BURNED',
        secretType: capsule.secretType,
        label: capsule.label,
        projectTag: capsule.projectTag,
        ciphertext,
        iv,
        burnedAt,
        crawlerHitsSurvived: capsule.crawlerHits,
        receiptHash: capsule.receiptHash
      });
    }

    // 6. Zero-Trust AI Rotation Advisor (POST /api/rotation-advice)
    if (req.method === 'POST' && pathname === '/api/rotation-advice') {
      try {
        const body = await readJsonBody(req);
        const validation = validateZeroTrustAiPayload(body.keyTypes);
        if (!validation.valid) {
          return sendJson(res, 400, {
            error: 'ZERO_TRUST_GUARDRAIL_BLOCKED',
            message: validation.reason
          });
        }

        const checklist = buildRotationChecklist(body.keyTypes);
        return sendJson(res, 200, {
          zeroTrustVerified: true,
          inspectedPayload: { keyTypes: body.keyTypes, valuesReceived: 0 },
          summary: `Generated rotation runbook for ${checklist.length} credential type(s).`,
          checklist
        });
      } catch (err) {
        return sendJson(res, 400, { error: 'BAD_REQUEST', message: err.message });
      }
    }

    // 7. Serve shared ES module /src/scrubber.mjs
    if (req.method === 'GET' && pathname === '/src/scrubber.mjs') {
      const scrubberPath = path.join(__dirname, 'src', 'scrubber.mjs');
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      return fs.createReadStream(scrubberPath).pipe(res);
    }

    // 8. Serve static frontend assets
    let relativePath = pathname === '/' ? '/index.html' : pathname;
    if (relativePath === '/console') {
      relativePath = '/console.html';
    }
    if (relativePath.startsWith('/v/')) {
      relativePath = '/reveal.html';
    }
    const safePath = path.normalize(relativePath).replace(/^(\.\.[/\\])+/, '');
    const filePath = path.join(__dirname, 'public', safePath);

    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
      return fs.createReadStream(filePath).pipe(res);
    }

    sendJson(res, 404, { error: 'NOT_FOUND', message: `Route ${pathname} not found.` });
}

export function createUnleakServer() {
  return http.createServer(handleRequest);
}

export default handleRequest;

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const PORT = process.env.PORT || 3847;
  const server = createUnleakServer();
  server.listen(PORT, () => {
    console.log(`UNLEAK server running at http://localhost:${PORT}`);
  });
}
