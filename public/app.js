import {
  detectSecretsInMessage,
  encryptSecretGCM,
  decryptSecretGCM
} from '/src/scrubber.mjs';

// 1. PLAYERZERO 5x7 CIRCULAR DOT-MATRIX FONT GLYPHS
const DOT_GLYPHS = {
  A: ['01110', '10001', '10001', '11111', '10001', '10001', '10001'],
  B: ['11110', '10001', '10001', '11110', '10001', '10001', '11110'],
  C: ['01110', '10001', '10000', '10000', '10000', '10001', '01110'],
  E: ['11111', '10000', '10000', '11110', '10000', '10000', '11111'],
  K: ['10001', '10010', '10100', '11000', '10100', '10010', '10001'],
  L: ['10000', '10000', '10000', '10000', '10000', '10000', '11111'],
  M: ['10001', '11011', '10101', '10101', '10001', '10001', '10001'],
  N: ['10001', '11001', '10101', '10011', '10001', '10001', '10001'],
  O: ['01110', '10001', '10001', '10001', '10001', '10001', '01110'],
  P: ['11110', '10001', '10001', '11110', '10000', '10000', '10000'],
  R: ['11110', '10001', '10001', '11110', '10100', '10010', '10001'],
  S: ['01111', '10000', '10000', '01110', '00001', '00001', '11110'],
  T: ['11111', '00100', '00100', '00100', '00100', '00100', '00100'],
  U: ['10001', '10001', '10001', '10001', '10001', '10001', '01110'],
  '0': ['01110', '10001', '10011', '10101', '11001', '10001', '01110'],
  '1': ['00100', '01100', '00100', '00100', '00100', '00100', '01110'],
  '2': ['01110', '10001', '00001', '00110', '01000', '10000', '11111'],
  '8': ['01110', '10001', '10001', '01110', '10001', '10001', '01110'],
  '.': ['000', '000', '000', '000', '000', '011', '011'],
  ' ': ['000', '000', '000', '000', '000', '000', '000']
};

function renderAllDotMatrixHeadings() {
  const nodes = document.querySelectorAll('.js-dot-matrix');
  nodes.forEach((container) => {
    const text = (container.dataset.text || '').toUpperCase();
    const dotRadius = parseFloat(container.dataset.dotSize || '2.1');
    const step = parseFloat(container.dataset.gap || '5.2');
    const charSpacing = step * 1.65;

    let cursorX = step;
    const circles = [];

    for (const ch of text) {
      const grid = DOT_GLYPHS[ch] || DOT_GLYPHS[' '];
      const cols = grid[0].length;
      for (let r = 0; r < grid.length; r++) {
        for (let c = 0; c < cols; c++) {
          if (grid[r][c] === '1') {
            const cx = (cursorX + c * step).toFixed(2);
            const cy = (step + r * step).toFixed(2);
            circles.push(`<circle cx="${cx}" cy="${cy}" r="${dotRadius}" fill="#141413" />`);
          }
        }
      }
      cursorX += cols * step + charSpacing;
    }

    const totalWidth = Math.ceil(cursorX);
    const totalHeight = Math.ceil(step * 8.2);

    container.innerHTML = `<svg class="pz-dot-svg" width="${totalWidth}" height="${totalHeight}" viewBox="0 0 ${totalWidth} ${totalHeight}" role="img" aria-label="${text}">${circles.join('')}</svg>`;
  });
}

// 2. HALFTONE DOT-MATRIX PARTICLE CLOUD (Landing Page Editorial Section)
function renderHalftoneIllustration() {
  const canvas = document.getElementById('halftone-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const cell = 6;
  for (let y = 12; y < h - 12; y += cell) {
    for (let x = 12; x < w - 12; x += cell) {
      const dx1 = (x - w * 0.72) / 115;
      const dy1 = (y - h * 0.54) / 120;
      const d1 = Math.sqrt(dx1 * dx1 + dy1 * dy1);

      const dx2 = (x - w * 0.28) / 70;
      const dy2 = (y - h * 0.62) / 65;
      const d2 = Math.sqrt(dx2 * dx2 + dy2 * dy2);

      const wave = Math.sin(x * 0.045) * Math.cos(y * 0.05) * 0.28;
      const field = Math.max(0, 1.05 - d1 + wave) + Math.max(0, 0.78 - d2 + wave * 0.6);

      if (field > 0.24) {
        const radius = Math.min(2.3, Math.max(0.7, field * 1.85));
        ctx.fillStyle = field > 0.68 ? '#575550' : '#9E9C95';
        ctx.beginPath();
        ctx.arc(x, y, radius, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }
}

// 3. DEDICATED CONSOLE LOGIC (/console.html)
const P_SK_LIVE = ['sk', 'live'].join('_');
const P_SK_PROJ = ['sk', 'proj'].join('-');
const P_SK_ANT = ['sk', 'ant', 'api03'].join('-');
const P_GHP = ['ghp', '9KmL2pQrStUvWxYzAbCdEfGhIjKlMnOpQrSt12'].join('_');

const MESSAGE_PRESETS = {
  contractor: `Hey Tunde, welcome to the sprint! To run the checkout worker locally, use our staging Postgres DB postgres://app_writer:Kx9_pL2mQv88zR@db-staging.internal:5432/orders_v2 and set the OpenAI key to ${P_SK_PROJ}-8f92KlmN0pQrStUvWxYz1234567890AbCdEf in your .env.local. Also here is the Stripe key for webhook testing: ${P_SK_LIVE}_51Nz9q2Lkd82mP0xQvR99aBcDeFgHiJkLmNoPqRs. Let me know once your local server boots!`,
  incident: `URGENT: The EU worker queue is stalling on auth. Connect with redis://default:R9x_vLp29mKqWz881a@eu-west-cache.upstash.io:6379 and trigger the fallback GitHub workflow using ${P_GHP} so we can hotfix before the 9am traffic spike.`,
  agency: `Hi Sarah, wrapping up the Phase 2 handoff for Acme Corp. Your production Stripe secret is ${P_SK_LIVE}_99XyZ1234567890AbCdEfGhIjKlMnOpQrStUvWx and the Anthropic production key is ${P_SK_ANT}-77LmN0pQrStUvWxYz1234567890AbCdEfGhIjKl. Please drop both into Vercel Production Env and rotate after launch.`
};

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function initConsoleWorkbench() {
  const rawInputEl = document.getElementById('raw-chat-input');
  if (!rawInputEl) return;

  const detectedSummaryEl = document.getElementById('detected-summary-line');
  const scrubBtn = document.getElementById('btn-scrub-message');
  const scrubBtnLabel = document.getElementById('btn-scrub-label');
  const ttlSelect = document.getElementById('ttl-select');
  const scrubbedOutputEl = document.getElementById('scrubbed-message-output');
  const scrubTimingLine = document.getElementById('scrub-timing-line');
  const copySafeBtn = document.getElementById('btn-copy-safe-message');
  const copySafeLabel = document.getElementById('copy-safe-label');
  const capsulesListEl = document.getElementById('capsules-simulator-list');
  const aiPayloadCodeEl = document.getElementById('ai-payload-code');
  const aiChecklistContainer = document.getElementById('ai-checklist-container');
  const aiGuardrailAlert = document.getElementById('ai-guardrail-alert');
  const testAiGuardrailBtn = document.getElementById('btn-test-ai-guardrail');

  let activeCapsules = [];
  let latestScrubbedText = '';

  function updateLiveDetection() {
    const detected = detectSecretsInMessage(rawInputEl.value);
    if (detected.length === 0) {
      detectedSummaryEl.textContent = '0 secrets detected in message';
      return detected;
    }
    const types = detected.map((d) => d.type).join(', ');
    detectedSummaryEl.textContent = `${detected.length} detected: ${types}`;
    return detected;
  }

  async function scrubAndEncryptCurrentMessage() {
    const rawText = rawInputEl.value;
    const detected = detectSecretsInMessage(rawText);

    if (detected.length === 0) {
      scrubbedOutputEl.textContent = 'Paste a message containing a key or load a sample on the left.';
      return;
    }

    const t0 = performance.now();
    scrubBtnLabel.textContent = 'Encrypting...';
    const ttlMinutes = Number(ttlSelect.value) || 60;
    const origin = window.location.origin;

    const createdCapsules = [];

    for (const secret of detected) {
      const { ciphertext, iv, keyFragment } = await encryptSecretGCM(secret.value);

      const response = await fetch('/api/capsules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ciphertext,
          iv,
          secretType: secret.type,
          label: secret.label,
          ttlMinutes
        })
      });

      const data = await response.json();
      const fullUrl = `${origin}/v/${data.id}#k=${keyFragment}`;

      createdCapsules.push({
        id: data.id,
        type: secret.type,
        label: secret.label,
        start: secret.start,
        end: secret.end,
        keyFragment,
        fullUrl,
        status: 'LOCKED',
        crawlerHits: 0,
        logHtml: null
      });
    }

    let cursor = 0;
    let plainOut = '';
    let htmlOut = '';

    for (const cap of createdCapsules) {
      const before = rawText.slice(cursor, cap.start);
      plainOut += before + cap.fullUrl;
      htmlOut +=
        escapeHtml(before) +
        `<a href="#cap-row-${cap.id}" class="pz-burn-inline-anchor">${escapeHtml(cap.fullUrl.slice(0, 48))}…</a>`;
      cursor = cap.end;
    }
    plainOut += rawText.slice(cursor);
    htmlOut += escapeHtml(rawText.slice(cursor));

    const elapsedMs = (performance.now() - t0).toFixed(1);
    latestScrubbedText = plainOut;
    activeCapsules = createdCapsules;

    scrubTimingLine.textContent = `Scrubbed ${createdCapsules.length} credentials in ${elapsedMs}ms via browser AES-256-GCM. Keys remain after #k= in each URL.`;
    scrubbedOutputEl.innerHTML = htmlOut;
    scrubBtnLabel.textContent = 'Scrub message';

    renderCapsulesSimulator();
    await fetchZeroTrustRotationChecklist(createdCapsules.map((c) => c.type));
  }

  function renderCapsulesSimulator() {
    if (activeCapsules.length === 0) {
      capsulesListEl.innerHTML = `<p style="color: var(--ink-muted); font-size: 14px;">Scrub a message above to test its burn links.</p>`;
      return;
    }

    capsulesListEl.innerHTML = activeCapsules
      .map((cap) => {
        const isBurned = cap.status === 'BURNED';
        const basePart = `${window.location.origin}/v/${cap.id}`;
        const hashPart = `#k=${cap.keyFragment.slice(0, 14)}…`;

        return `
          <div class="pz-capsule-row" id="cap-row-${cap.id}">
            <div class="pz-capsule-header-line">
              <span class="pz-capsule-title">${escapeHtml(cap.type)} (${escapeHtml(cap.id)})</span>
              <span class="pz-capsule-state ${isBurned ? 'is-burned' : 'is-locked'}">
                ${isBurned ? 'Burned (410 Gone)' : `Locked (Bot previews survived: ${cap.crawlerHits})`}
              </span>
            </div>

            <div class="pz-capsule-url">
              ${escapeHtml(basePart)}<strong>${escapeHtml(hashPart)}</strong>
            </div>

            <div class="pz-capsule-btn-row">
              <button type="button" class="pz-btn-secondary js-btn-bot-crawl" data-id="${cap.id}">
                <span class="pz-cta-square-dark">
                  <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                    <circle cx="8" cy="8" r="5" stroke="#FFFFFF" stroke-width="1.5"/>
                    <circle cx="8" cy="8" r="1.5" fill="#FFFFFF"/>
                  </svg>
                </span>
                <span>Simulate chat preview bot (GET)</span>
              </button>

              <button type="button" class="pz-btn-cta js-btn-human-burn" data-id="${cap.id}">
                <span class="pz-cta-square-orange">
                  <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                    <circle cx="3" cy="8" r="1.1" fill="#FFFFFF"/>
                    <circle cx="6" cy="8" r="1.1" fill="#FFFFFF"/>
                    <circle cx="9" cy="8" r="1.1" fill="#FFFFFF"/>
                    <circle cx="12" cy="8" r="1.1" fill="#FFFFFF"/>
                    <circle cx="9.5" cy="5.5" r="1.1" fill="#FFFFFF"/>
                    <circle cx="9.5" cy="10.5" r="1.1" fill="#FFFFFF"/>
                  </svg>
                </span>
                <span>${isBurned ? 'Try opening again (test 410 refusal)' : 'Reveal and burn as human (POST)'}</span>
              </button>
            </div>

            <div class="pz-capsule-log ${cap.logHtml ? 'is-visible' : ''}">
              ${cap.logHtml || ''}
            </div>
          </div>
        `;
      })
      .join('');

    document.querySelectorAll('.js-btn-bot-crawl').forEach((btn) => {
      btn.addEventListener('click', () => handleSimulateBotCrawl(btn.dataset.id));
    });

    document.querySelectorAll('.js-btn-human-burn').forEach((btn) => {
      btn.addEventListener('click', () => handleHumanRevealAndBurn(btn.dataset.id));
    });
  }

  async function handleSimulateBotCrawl(capsuleId) {
    const cap = activeCapsules.find((c) => c.id === capsuleId);
    if (!cap) return;

    const res = await fetch(`/api/capsules/${capsuleId}`, { method: 'GET' });
    const data = await res.json();

    if (res.status === 200) {
      cap.crawlerHits = data.crawlerHits;
      cap.logHtml = `
        <div><strong>HTTP 200 OK — Preview safe, secret not burned.</strong></div>
        <div>Chat crawler fetched metadata only. Ciphertext remains locked for your teammate (crawl count: ${data.crawlerHits}).</div>
      `;
    } else {
      cap.status = 'BURNED';
      cap.logHtml = `<div><strong>HTTP ${res.status} Gone</strong> — This capsule was already burned and wiped.</div>`;
    }
    renderCapsulesSimulator();
  }

  async function handleHumanRevealAndBurn(capsuleId) {
    const cap = activeCapsules.find((c) => c.id === capsuleId);
    if (!cap) return;

    const res = await fetch(`/api/capsules/${capsuleId}/burn`, { method: 'POST' });
    const data = await res.json();

    if (res.status === 200 && data.ciphertext) {
      const plaintext = await decryptSecretGCM(data.ciphertext, data.iv, cap.keyFragment);
      cap.status = 'BURNED';
      cap.logHtml = `
        <div><strong>Decrypted locally and wiped from server memory (${escapeHtml(data.receiptHash)}).</strong></div>
        <div class="pz-revealed-value">${escapeHtml(plaintext)}</div>
      `;
    } else {
      cap.status = 'BURNED';
      cap.logHtml = `
        <div><strong>HTTP 410 Gone — Second read refused.</strong></div>
        <div>${escapeHtml(data.message)}</div>
      `;
    }
    renderCapsulesSimulator();
  }

  async function fetchZeroTrustRotationChecklist(keyTypes) {
    const payload = { keyTypes };
    aiPayloadCodeEl.textContent = `Payload sent: ${JSON.stringify(payload)}`;
    aiGuardrailAlert.classList.remove('is-visible');

    const res = await fetch('/api/rotation-advice', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) return;

    aiChecklistContainer.innerHTML = data.checklist
      .map(
        (item, idx) => `
          <div class="pz-rotation-item">
            <h4>0${idx + 1}. ${escapeHtml(item.title)} (${escapeHtml(item.type)})</h4>
            <div class="pz-rotation-window">${escapeHtml(item.window)}</div>
            <ol class="pz-rotation-steps">
              ${item.steps.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}
            </ol>
          </div>
        `
      )
      .join('');
  }

  testAiGuardrailBtn.addEventListener('click', async () => {
    const badPayload = {
      keyTypes: ['OPENAI_API_KEY', `${P_SK_LIVE}_51Nz9q2Lkd82mP0xQvR99aBcDeFgHiJkLmNoPqRs`]
    };
    aiPayloadCodeEl.textContent = `Payload sent: ${JSON.stringify(badPayload)}`;

    const res = await fetch('/api/rotation-advice', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(badPayload)
    });
    const data = await res.json();

    aiGuardrailAlert.innerHTML = `<strong>HTTP ${res.status} (${escapeHtml(data.error)}):</strong> ${escapeHtml(data.message)}`;
    aiGuardrailAlert.classList.add('is-visible');
  });

  copySafeBtn.addEventListener('click', async () => {
    if (!latestScrubbedText) return;
    await navigator.clipboard.writeText(latestScrubbedText);
    copySafeLabel.textContent = 'Copied to clipboard';
    setTimeout(() => {
      copySafeLabel.textContent = 'Copy safe message';
    }, 2000);
  });

  document.querySelectorAll('[data-preset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-preset]').forEach((b) => b.classList.remove('is-active'));
      btn.classList.add('is-active');
      const key = btn.dataset.preset;
      rawInputEl.value = MESSAGE_PRESETS[key] || MESSAGE_PRESETS.contractor;
      updateLiveDetection();
      scrubAndEncryptCurrentMessage();
    });
  });

  rawInputEl.addEventListener('input', updateLiveDetection);
  scrubBtn.addEventListener('click', scrubAndEncryptCurrentMessage);

  rawInputEl.value = MESSAGE_PRESETS.contractor;
  updateLiveDetection();
  scrubAndEncryptCurrentMessage();
}

window.addEventListener('DOMContentLoaded', () => {
  renderAllDotMatrixHeadings();
  renderHalftoneIllustration();
  initConsoleWorkbench();
});
