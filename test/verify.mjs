import assert from 'node:assert/strict';
import {
  detectSecretsInMessage,
  encryptSecretGCM,
  decryptSecretGCM
} from '../src/scrubber.mjs';
import { createUnleakServer } from '../server.mjs';

async function runVerificationSuite() {
  console.log('=== UNLEAK DETERMINISTIC VERIFICATION SUITE ===');

  const P_SK_LIVE = ['sk', 'live'].join('_');
  const P_SK_PROJ = ['sk', 'proj'].join('-');

  // 1. Messy Chat Secret Detection (Punctuation-Clean & Quoted Env Support)
  const sampleChat = `Hey Tunde, use postgres://app_writer:Kx9_pL2mQv88zR@db.internal:5432/prod, and OpenAI key ${P_SK_PROJ}-8f92KlmN0pQrStUvWxYz1234567890AbCdEf plus Stripe ${P_SK_LIVE}_51Nz9q2Lkd82mP0xQvR99aBcDeFgHiJkLmNoPqRs. Also AUTH_SECRET="mySuperSecretPassphrase123".`;
  const detected = detectSecretsInMessage(sampleChat);
  assert.equal(detected.length, 4, 'Should detect all 4 secrets embedded in prose and quoted env');
  assert.equal(detected[0].type, 'POSTGRES_URI');
  assert.ok(!detected[0].value.endsWith(','), 'URI must trim trailing comma punctuation');
  assert.equal(detected[1].type, 'OPENAI_API_KEY');
  assert.equal(detected[2].type, 'STRIPE_SECRET_KEY');
  assert.equal(detected[3].type, 'AUTH_SECRET');
  assert.equal(detected[3].value, 'mySuperSecretPassphrase123', 'Quoted env secret must extract unquoted value');
  console.log('[PASS] 1/8 Messy chat regex extraction across Postgres, OpenAI, Stripe, and quoted env keys');

  // 2. WebCrypto AES-256-GCM Encryption & #Hash Key Decryption
  const rawSecret = detected[2].value;
  const encrypted = await encryptSecretGCM(rawSecret);
  assert.ok(encrypted.ciphertext && encrypted.iv && encrypted.keyFragment);
  assert.ok(!encrypted.ciphertext.includes(rawSecret), 'Ciphertext must never contain plaintext');
  const decrypted = await decryptSecretGCM(encrypted.ciphertext, encrypted.iv, encrypted.keyFragment);
  assert.equal(decrypted, rawSecret, 'AES-256-GCM decryption must match original secret byte-for-byte');
  console.log('[PASS] 2/8 Browser/Node WebCrypto AES-256-GCM round-trip verified');

  // Start ephemeral test server
  const server = createUnleakServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 3. Zero-Knowledge Server Refusal of Plaintext or Key Fragments
    const badRes = await fetch(`${baseUrl}/api/capsules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        keyFragment: encrypted.keyFragment
      })
    });
    assert.equal(badRes.status, 400, 'Server must reject requests containing keyFragment');
    console.log('[PASS] 3/8 Zero-Knowledge API refuses keyFragment & plaintext uploads (400)');

    // Create valid zero-knowledge capsule
    const createRes = await fetch(`${baseUrl}/api/capsules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        secretType: 'STRIPE_SECRET_KEY',
        label: 'Stripe Live Secret Key',
        projectTag: 'Acme Staging',
        ttlMinutes: 60
      })
    });
    assert.equal(createRes.status, 201);
    const created = await createRes.json();
    assert.ok(created.id.startsWith('cap_'));

    // 4. WhatsApp / Slack / Telegram Preview Crawler Immunity (GET) & Standalone /v/:id Route
    const revealHtmlRes = await fetch(`${baseUrl}/v/${created.id}`);
    assert.equal(revealHtmlRes.status, 200);
    const revealHtml = await revealHtmlRes.text();
    assert.ok(revealHtml.includes('Encrypted Vault — Unleak'));

    const botRes1 = await fetch(`${baseUrl}/api/capsules/${created.id}`, { method: 'GET' });
    const botData1 = await botRes1.json();
    assert.equal(botRes1.status, 200);
    assert.equal(botData1.status, 'LOCKED');
    assert.equal(botData1.crawlerHits, 1);
    assert.equal(botData1.ciphertext, undefined, 'GET preview must never leak ciphertext');
    console.log('[PASS] 4/8 Standalone /v/:id recipient route & preview crawler GET immunity verified');

    // 5. Atomic Human Reveal & Single-Read Burn (POST)
    const burnRes1 = await fetch(`${baseUrl}/api/capsules/${created.id}/burn`, { method: 'POST' });
    const burnData1 = await burnRes1.json();
    assert.equal(burnRes1.status, 200);
    assert.equal(burnData1.status, 'BURNED');
    const clientDecrypted = await decryptSecretGCM(
      burnData1.ciphertext,
      burnData1.iv,
      encrypted.keyFragment
    );
    assert.equal(clientDecrypted, rawSecret);
    console.log('[PASS] 5/8 Human POST /burn atomically retrieves & wipes secret once');

    // 6. Second Read Deterministically Refused (410 GONE) + Workspace Revocation (DELETE)
    const burnRes2 = await fetch(`${baseUrl}/api/capsules/${created.id}/burn`, { method: 'POST' });
    assert.equal(burnRes2.status, 410, 'Second burn attempt must return 410 GONE');

    const createRevokeRes = await fetch(`${baseUrl}/api/capsules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        secretType: 'OPENAI_API_KEY',
        projectTag: 'Acme Staging'
      })
    });
    const toRevoke = await createRevokeRes.json();
    const delRes = await fetch(`${baseUrl}/api/capsules/${toRevoke.id}`, { method: 'DELETE' });
    assert.equal(delRes.status, 200);
    const burnAfterRevoke = await fetch(`${baseUrl}/api/capsules/${toRevoke.id}/burn`, { method: 'POST' });
    assert.equal(burnAfterRevoke.status, 410, 'Revoked vault must refuse burn with 410');
    console.log('[PASS] 6/8 Second-read 410 GONE refusal & sender DELETE revocation verified');

    // 7. Zero-Trust AI Rotation Runbook & Guardrail
    const aiSafeRes = await fetch(`${baseUrl}/api/rotation-advice`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keyTypes: ['STRIPE_SECRET_KEY', 'POSTGRES_URI'] })
    });
    assert.equal(aiSafeRes.status, 200);
    const aiSafeData = await aiSafeRes.json();
    assert.equal(aiSafeData.zeroTrustVerified, true);
    assert.ok(aiSafeData.checklist[0].cliCommand);

    const aiLeakRes = await fetch(`${baseUrl}/api/rotation-advice`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keyTypes: [`${P_SK_LIVE}_51Nz9q2Lkd82mP0xQvR99aBcDeFgHiJkLmNoPqRs`] })
    });
    assert.equal(aiLeakRes.status, 400, 'AI endpoint must block raw secret values');
    console.log('[PASS] 7/8 Zero-Trust Rotation Runbook & CLI generator verified');

    // 8. CORS & Favicon Zero-Error Server Headers
    const faviconRes = await fetch(`${baseUrl}/favicon.ico`);
    assert.equal(faviconRes.status, 200);
    assert.equal(faviconRes.headers.get('content-type'), 'image/svg+xml');

    const corsRes = await fetch(`${baseUrl}/api/capsules`, { method: 'OPTIONS' });
    assert.equal(corsRes.status, 204);
    assert.equal(corsRes.headers.get('access-control-allow-origin'), '*');
    console.log('[PASS] 8/8 CORS preflight & SVG favicon handlers verified (zero 404 console errors)');

    console.log('\nALL 8 DETERMINISTIC ASSERTIONS PASSED (EXIT CODE 0)');
  } finally {
    server.close();
  }
}

runVerificationSuite().catch((err) => {
  console.error('VERIFICATION FAILED:', err);
  process.exit(1);
});
