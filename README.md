# Unleak

[![License: MIT](https://img.shields.io/badge/License-MIT-141413.svg)](./LICENSE)
[![Tests: 6/6 Passing](https://img.shields.io/badge/Tests-6%2F6_Passing_Deterministically-1D6F4A.svg)](./test/verify.mjs)
[![Encryption: WebCrypto AES-256-GCM](https://img.shields.io/badge/Crypto-Browser_AES--256--GCM-DE6347.svg)](./src/scrubber.mjs)

**Stop pasting live API keys and database URLs into team chat.** Unleak takes any messy chat paragraph, finds the embedded secrets by regex in your browser, encrypts each one separately with `AES-256-GCM`, and hands back the exact same sentence with bot-safe, one-time burn links.

---

## Why Plain Secret Boxes Fail in Real Team Chat

1. **People don't paste clean `.env` files—they paste messy sentences.**
   Standard one-time secret tools force you to manually cut each key out of your paragraph, generate separate links, and rewrite your message. Unleak scrubs the keys in place while keeping your conversation intact.
2. **WhatsApp, Telegram, and Slack preview bots eat naive burn links.**
   Chat apps automatically send a `GET` request to every shared URL to build a link preview card. If a secret burns on first `GET`, the chat crawler destroys the credential before your teammate clicks it. Unleak separates `GET` preview metadata from an atomic human `POST /burn` delete operation.
3. **Zero-Trust AI Rotation Advisor.**
   Sending secret values to an LLM violates zero-knowledge security. After a burn, Unleak sends **only the variable type names** (e.g. `["STRIPE_SECRET_KEY", "POSTGRES_URI"]`) to generate a prioritized post-handoff rotation checklist.

---

## Architecture Flow

```text
[Messy Chat Message in Browser]
       │
       ├──► 1. Client-Side Regex Extractor (src/scrubber.mjs)
       │       Spots sk_live_*, sk-proj-*, postgres://*, redis://*, ghp_*, AKIA*
       │
       ├──► 2. Browser WebCrypto AES-256-GCM
       │       • Ciphertext + 96-bit IV ──► POST /api/capsules (Stored in memory)
       │       • 256-bit Key (#k=...)   ──► Stays strictly in URL #hash fragment
       │
       ├──► 3. Bot-Safe Preview Gate vs. Atomic Burn
       │       • GET  /api/capsules/:id      ──► 200 OK Preview (Bots cannot burn)
       │       • POST /api/capsules/:id/burn ──► Atomic single-read & memory wipe
       │       • 2nd  POST /api/capsules/:id ──► 410 GONE (Deterministic refusal)
       │
       └──► 4. Zero-Trust AI Rotation Advisor (POST /api/rotation-advice)
               • Inspects ONLY variable type names (blocks raw secret values with 400)
```

---

## Quick Start & Deterministic Verification

```bash
# 1. Run the 6-assertion deterministic verification suite (exits with code 0)
npm test

# 2. Start the Unleak server (Landing Page at / and Console at /console.html)
npm start
```

---

## Verified Benchmark & Test Receipts (`node test/verify.mjs`)

| Assertion | Verified Mechanism | Status |
| :--- | :--- | :--- |
| **1. Inline Chat Regex** | Extracts `POSTGRES_URI`, `OPENAI_API_KEY`, and `STRIPE_SECRET_KEY` from natural prose | `PASS` |
| **2. Browser AES-256-GCM** | Encrypts & decrypts via WebCrypto subtle API with 256-bit `#hash` key | `PASS` |
| **3. Zero-Knowledge Refusal** | Server rejects any `POST /api/capsules` containing `keyFragment` or `plaintext` (`400`) | `PASS` |
| **4. Crawler `GET` Immunity** | Simulated Slack/WhatsApp preview bots hit `GET` twice without burning ciphertext | `PASS` |
| **5. Atomic `POST` Burn** | First human `POST /burn` retrieves ciphertext once and wipes server memory | `PASS` |
| **6. `410 GONE` & AI Guardrail** | Second `POST /burn` returns `410 Gone`; raw keys sent to AI return `400 Blocked` | `PASS` |

---

## Commercial Model

* **Free Forever ($0):** Unlimited chat scrubbing and one-time burn links for individual developers (every recipient who opens a burn link discovers Unleak organically).
* **Agency & Freelancer Pro ($9/month):** Built for software agencies handing off client credentials who need custom expiry windows (`5m` to `7d`) and signed *"Opened & Burned"* compliance receipts.
