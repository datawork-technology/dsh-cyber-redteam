# Changelog

All notable changes to `dsh-cyber-redteam`. The command surface stays
`/cyber`, `/cyber-2`, `/cyberoff`, and `/cyber-mode on|off|status`.

## 0.6.1 — 2026-11-10

Reach upstreams that send an incomplete certificate chain.

- When TLS verification fails because the server skipped its intermediate
  certificate, the gateway fetches that issuer from the leaf's Authority
  Information Access extension and retries once with it added to the trusted
  roots. Verification stays on: the repaired chain must still reach a local
  root, so this is not `rejectUnauthorized: false`.
- The repaired connection answers with `x-cyberops-tls-chain:
  completed-from-aia`, and the CA bundle is cached per host until it fails.
- Chain failures (`UNABLE_TO_VERIFY_LEAF_SIGNATURE`,
  `UNABLE_TO_GET_ISSUER_CERT*`, `SELF_SIGNED_CERT_IN_CHAIN`,
  `DEPTH_ZERO_SELF_SIGNED_CERT`, `CERT_UNTRUSTED`) now diagnose as
  `upstream-tls-failed` instead of the generic `upstream-unavailable`, so an
  agent stops treating a misconfigured certificate as a transient outage.
- Only GET/HEAD are replayed; a request with a body reports the TLS diagnosis
  instead of resending it.

## 0.6.0 — 2026-11-10

One masked listener and port per route.

- Every masked route now owns its own loopback listener. Two chats that target
  the same origin get different ports as well as different tokens, and two
  routes in one chat never share a port.
- A route's port is persisted in state schema v2 and rebound on boot. A port
  another process took falls back to an ephemeral one and is re-persisted.
- Retiring a route closes its listener, so a revoked masked URL stops
  answering instead of returning a stale page.
- A token from one route answers 404 on another route's port.
- `projectPrompt()` and `projectMessage()` are async because binding a port is.
  The `agent/pre-step` hook awaits them.
- State written by 0.5.x (v1: one shared port) still loads; each route starts on
  an ephemeral port and persists it.
- The route list in the system prompt now states that every route has its own
  base and that bases must not be spliced together.

## 0.5.2 — 2026-11-10

Masking follows the Red Team toggle.

- A URL pasted in a chat that never armed CyberOps stays exactly as typed: no
  route is registered and no link is rewritten.
- Arming via the toggle, or an explicit `/cyber` or `/cyber-2`, opts that chat
  in; `/cyberoff` opts it out immediately.
- Routes persisted by a disarmed session are dropped on load, so a legacy
  masked token is never resurrected.

## 0.5.1 — 2026-11-10

First public release, and per-chat, per-activation token identity.

- Route tokens are minted with a fresh 128-bit nonce mixed into an HMAC keyed by
  the install secret and bound to the owning session and origin. They are
  checked against the whole route table, so two chats never share a token.
- `/cyberoff`, disarming, or clearing a session deletes the route; authorizing
  the same target again mints a new token, so a leaked URL stays dead.
- A token is stable within one activation (re-projection does not rotate it) and
  across a restart (it is persisted).
- The bundle patch is portable: `toolkitRoot`, `allowPrivateTargets`, and
  `statePath` belong in a profile patch, not in the bundle.
- MIT license, public market index, and a documented masking identity.
