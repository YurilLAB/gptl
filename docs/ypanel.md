# Connecting GPTL to ypanel

**ypanel** is Yuril Security's unified operator control panel — a single web app
(served at `https://yurillab.dev/ypanel`) for running the whole Yuril suite
(QPot, DireC, WEWAF, Kmap, GPTL) from one place, scoped to the licences an
operator owns. In ypanel, **GPTL** is the anonymity-network console: relays,
circuits, streams, and — crucially — an honest capabilities scorecard.

This document defines how a GPTL client/relay connects to ypanel.

## Honesty first (this is the product's ethos)

GPTL is a **research implementation**. The cryptographic transport is real, but
much of the advertised defence surface is implemented as standalone library code
that is **not yet wired into the live data path** (see this repo's README
"Implementation status"). ypanel reflects that split faithfully and never
presents a designed-but-unwired defence as protecting live traffic:

- **Active in the live SOCKS5 → relay data path** (8): authenticated ntor
  handshake, per-hop layered AEAD (1-/2-hop), fixed 512-byte cells,
  random-interval padding, persistent entry guards, circuit-pool pre-building,
  relay-side exit policy, relay resource caps.
- **Partial** (1): pinned-ed25519 directory verification (no full consensus).
- **Designed, not wired** (10): the whole `gptl-core::anti_surveillance`
  pipeline and the whole `gptl-routing` crate.

ypanel's **GPTL → Capabilities** page is exactly this scorecard. If a defence
moves from "designed" to "active" in the code, update the capability model and
the panel reflects it — the panel must never overstate the shipped data path.

## The operator-plane model

```
  GPTL client/relay ──phone-home──▶ activation worker ──reads──▶ ypanel (browser)
  (circuits, guards,                 (operator plane)            (operator session,
   relay directory, padding)                                       licence-scoped)
```

ypanel's GPTL section surfaces relays (role/flags/bandwidth/signed status),
circuits (the guard→middle→exit hop chain, latency, padding, bytes), and
streams. Control actions (build/close circuit, rotate guards) are queued jobs the
client applies — never executed from the browser.

### Security model (load-bearing)

- **Headers-only secrets** (operator session + client licence key); HTTPS
  enforced. Relay/client private keys never reach the browser.
- **Tenant isolation** + an **allow-listed** control vocabulary. **Fail-closed**
  reads — no stale circuit/relay state when the link is down.
- The capabilities scorecard is part of the security model: it keeps the
  operator honest about what is actually defending live traffic.

## Status today (honest)

| Capability | Status |
|------------|--------|
| GPTL transport: ntor handshake, layered AEAD, fixed cells, padding, guards, exit policy | **implemented** (this repo) |
| `gptl-core::anti_surveillance`, `gptl-routing` (BGP/RPKI, Sybil, PoW, DNS/WebRTC-leak) | **implemented but not wired into the live path** |
| Full consensus / multi-authority directory | **not implemented** (pinned-ed25519 verification only) |
| ypanel GPTL section (Overview/Relays/Circuits/Capabilities/Settings) | **implemented** — honest demo today; the capability split is truthful |
| Client/relay → worker telemetry + operator job queue | **planned** — this doc defines the contract |

Until the operator-plane endpoints for GPTL are deployed, ypanel's GPTL screens
run on honest **Demo data**, and the Capabilities page states the real
active/designed split.
