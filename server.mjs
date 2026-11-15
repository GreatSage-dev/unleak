import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { validateZeroTrustAiPayload } from './src/scrubber.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// In-memory atomic capsule store (mirrors Upstash Redis atomic GETDEL semantics)
export const capsuleStore = new Map();

const ROTATION_PLAYBOOKS = {
  STRIPE_SECRET_KEY: {
    priority: 1,
    title: 'Restrict & Roll Stripe Secret Key',
    window: 'Immediate (Financial Settlement Access)',
    steps: [
      'Open Stripe Dashboard → Developers → API Keys and replace the shared sk_live_ key with a Restricted Key (rk_live_) scoped only to required resources.',
      'Set key expiration or roll the key with a 24-hour grace window once contractor setup is verified.',
      'Verify webhook signing secrets (whsec_) are bound to a single staging/production endpoint.'
    ]
  },
  POSTGRES_URI: {
    priority: 2,
    title: 'Scope PostgreSQL Role & Enforce SSL',
    window: 'Within 2 hours of handoff',
    steps: [
      'Replace superuser credentials in the URI with a dedicated least-privilege role (GRANT SELECT, INSERT, UPDATE ON TABLE ...).',
      'Append ?sslmode=require to the connection string and restrict IP ingress or PgBouncer pool limits.',
      'Run ALTER USER <role> WITH PASSWORD after the contractor session or migration completes.'
    ]
  },
  OPENAI_API_KEY: {
    priority: 3,
    title: 'Project-Scope OpenAI Key & Hard Spend Cap',
    window: 'Within 4 hours of handoff',
    steps: [
      'Move from user-level keys to a dedicated Project Service Account key (sk-proj-...) in platform.openai.com.',
      'Set a hard monthly dollar budget limit and restrict model permissions to only required endpoints.',
      'Revoke the temporary onboarding key immediately after environment variables are loaded into Vercel/Render.'
    ]
  },
  ANTHROPIC_API_KEY: {
    priority: 3,
    title: 'Workspace-Limit Anthropic Key',
    window: 'Within 4 hours of handoff',
    steps: [
      'Assign the key to an isolated Anthropic Console Workspace with a strict monthly token spend cap.',
      'Rotate the key via Console → API Keys once deployed to the target server.'
    ]
  },
  AWS_ACCESS_KEY: {
    priority: 1,
    title: 'Deactivate Static IAM Key & Migrate to OIDC/STS',
    window: 'Immediate (Cloud Infrastructure Access)',
    steps: [
      'Open AWS IAM → Users → Security Credentials and verify CloudTrail usage logs for the shared AKIA key.',
      'Attach an inline IAM boundary restricting access strictly to the target S3 bucket or Lambda resource.',
      'Deactivate and delete the static AKIA key after handoff in favor of short-lived STS AssumeRole sessions.'
    ]
  },
  GITHUB_TOKEN: {
    priority: 2,
    title: 'Convert Classic PAT to Fine-Grained Repository Token',
    window: 'Within 4 hours of handoff',
    steps: [
      'Ensure the token is a Fine-Grained Personal Access Token scoped to a single repository with 7-day expiry.',
      'Remove write:packages or admin:org scopes if only repo contents read/write is needed.'
    ]
  },
  REDIS_URI: {
    priority: 3,
    title: 'Enable Redis ACL User Rules',
    window: 'Within 24 hours',
    steps: [
      'Create a scoped ACL user (ACL SETUSER contractor on >pass ~cache:* +get +set -flushall).',
      'Rotate the default Redis password once local testing concludes.'
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
      window: 'After contractor/teammate onboarding',
      steps: [
        `Confirm ${type} has been moved into a local .env.local or deployment secret manager (never committed to git).`,
        `Issue a scoped replacement credential and revoke this temporary handoff secret once setup is verified.`
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
      } catch (err) {
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

export function createUnleakServer() {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    // 1. Create Encrypted Capsule (Zero-Knowledge: server never receives keyFragment or plaintext)
    if (req.method === 'POST' && pathname === '/api/capsules') {
      try {
        const body = await readJsonBody(req);
        if (body.plaintext || body.keyFragment || body.rawSecret) {
          return sendJson(res, 400, {
            error: 'ZERO_KNOWLEDGE_VIOLATION',
            message: 'Server refuses plaintext or decryption key fragments. Encrypt in browser first.'
          });
        }
        const { ciphertext, iv, secretType = 'SECRET', label = 'Encrypted Secret', ttlMinutes = 60 } = body;
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
          ciphertext,
          iv,
          createdAt: new Date(now).toISOString(),
          expiresAt: new Date(expiresAt).toISOString(),
          expiresAtMs: expiresAt,
          crawlerHits: 0,
          burned: false,
          burnedAt: null,
          receiptHash: null
        });

        return sendJson(res, 201, {
          id,
          secretType,
          label,
          createdAt: new Date(now).toISOString(),
          expiresAt: new Date(expiresAt).toISOString(),
          status: 'LOCKED'
        });
      } catch (err) {
        return sendJson(res, 400, { error: 'BAD_REQUEST', message: err.message });
      }
    }

    // 2. Bot-Safe Preview Check (GET /api/capsules/:id)
    // WhatsApp, Slack, Telegram, Discord link-preview bots hit GET.
    // This NEVER burns the secret or exposes ciphertext.
    const capsuleMatch = pathname.match(/^\/api\/capsules\/([a-zA-Z0-9_]+)$/);
    if (req.method === 'GET' && capsuleMatch) {
      const id = capsuleMatch[1];
      const capsule = capsuleStore.get(id);

      if (!capsule) {
        return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Capsule not found.' });
      }

      if (Date.now() > capsule.expiresAtMs && !capsule.burned) {
        capsule.ciphertext = null;
        capsule.iv = null;
        capsule.burned = true;
        capsule.burnedAt = new Date().toISOString();
      }

      if (capsule.burned) {
        return sendJson(res, 410, {
          id: capsule.id,
          status: 'BURNED',
          secretType: capsule.secretType,
          label: capsule.label,
          burnedAt: capsule.burnedAt,
          receiptHash: capsule.receiptHash,
          crawlerHits: capsule.crawlerHits,
          message: 'This capsule was already opened and permanently destroyed.'
        });
      }

      capsule.crawlerHits += 1;
      return sendJson(res, 200, {
        id: capsule.id,
        status: 'LOCKED',
        secretType: capsule.secretType,
        label: capsule.label,
        createdAt: capsule.createdAt,
        expiresAt: capsule.expiresAt,
        crawlerHits: capsule.crawlerHits,
        botPreviewSafe: true,
        message: 'Capsule is intact. Preview crawlers cannot burn this link; human POST required.'
      });
    }

    // 3. Atomic Human Reveal & Burn (POST /api/capsules/:id/burn)
    const burnMatch = pathname.match(/^\/api\/capsules\/([a-zA-Z0-9_]+)\/burn$/);
    if (req.method === 'POST' && burnMatch) {
      const id = burnMatch[1];
      const capsule = capsuleStore.get(id);

      if (!capsule) {
        return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Capsule does not exist.' });
      }

      if (capsule.burned || !capsule.ciphertext || Date.now() > capsule.expiresAtMs) {
        return sendJson(res, 410, {
          id: capsule.id,
          status: 'BURNED',
          burnedAt: capsule.burnedAt,
          receiptHash: capsule.receiptHash,
          message: '410 GONE: Secret was already burned and wiped from server memory.'
        });
      }

      // Atomic single-read extraction & immediate memory wipe (GETDEL semantics)
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
      capsule.burnedAt = burnedAt;
      capsule.receiptHash = `burn_${receiptHash}`;

      return sendJson(res, 200, {
        id: capsule.id,
        status: 'BURNED',
        secretType: capsule.secretType,
        label: capsule.label,
        ciphertext,
        iv,
        burnedAt,
        crawlerHitsSurvived: capsule.crawlerHits,
        receiptHash: capsule.receiptHash
      });
    }

    // 4. Zero-Trust AI Rotation Advisor (POST /api/rotation-advice)
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
          summary: `Generated post-handoff rotation plan for ${checklist.length} credential type(s) without inspecting secret values.`,
          checklist
        });
      } catch (err) {
        return sendJson(res, 400, { error: 'BAD_REQUEST', message: err.message });
      }
    }

    // 5. Serve shared ES module /src/scrubber.mjs
    if (req.method === 'GET' && pathname === '/src/scrubber.mjs') {
      const scrubberPath = path.join(__dirname, 'src', 'scrubber.mjs');
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      return fs.createReadStream(scrubberPath).pipe(res);
    }

    // 6. Serve static frontend assets from /public
    let relativePath = pathname === '/' ? '/index.html' : pathname;
    if (relativePath === '/console') {
      relativePath = '/console.html';
    }
    if (relativePath.startsWith('/v/')) {
      relativePath = '/console.html';
    }
    const safePath = path.normalize(relativePath).replace(/^(\.\.[/\\])+/, '');
    const filePath = path.join(__dirname, 'public', safePath);

    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
      return fs.createReadStream(filePath).pipe(res);
    }

    sendJson(res, 404, { error: 'NOT_FOUND', message: `Route ${pathname} not found.` });
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const PORT = process.env.PORT || 3847;
  const server = createUnleakServer();
  server.listen(PORT, () => {
    console.log(`UNLEAK server running at http://localhost:${PORT}`);
  });
}
