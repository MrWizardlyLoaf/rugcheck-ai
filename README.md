# 🛡️ RugCheck AI — On-chain Token Safety for Solana AI Agents

![version](https://img.shields.io/badge/version-1.2.0-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![MCP](https://img.shields.io/badge/MCP-Registry-7c3aed)
![python](https://img.shields.io/badge/python-3.12-3776ab)
![transport](https://img.shields.io/badge/transport-Streamable_HTTP-success)
![CI](https://github.com/MrWizardlyLoaf/rugcheck-ai/actions/workflows/ci.yml/badge.svg)

A lightweight MCP server that reads a Solana token's mint **directly from the chain** to screen for
the common rug & honeypot traps **before** your agent trades — active mint/freeze authority and
dangerous Token-2022 extensions (permanent delegate, transfer hooks, non-transferable, pausable) —
then, for tokens that pass, builds the buy as an **unsigned** Jupiter transaction carrying a small Jito
tip for faster inclusion. You sign it; the server never holds keys.

## Quickstart (30 seconds)

No install, no API key. Point your agent at the remote endpoint:

```
https://web-production-58d585.up.railway.app/mcp
```

Then ask one question before any buy:

```
scan_token("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263")   # BONK
→ { verdict: "SAFE", safety_score: 100, sellable: true, risks: ["no red flags found"] }
```

`SAFE` → clear. `CAUTION` → read the risks. `DANGER` → don't buy. That's the whole loop.

## See it catch a rug

Three real mainnet tokens, one `scan_token` call each (scanned 2026-06-17 — re-run to verify, live state changes):

| Token | Verdict | Why |
|---|---|---|
| **BONK** | `SAFE` · 100 | authority renounced, liquid, sellable — no red flags |
| **USDC** | `CAUTION` · 70 | issuer keeps an active mint **and** freeze authority — your balance *can* be frozen |
| fresh pump token `24tF…i9pump` | `DANGER` · 20 | **no sell route** (honeypot), **100%** held by one wallet, **$0** liquidity |

The honeypot is the one that matters: you could buy it and never sell. RugCheck AI flags it **before** your
agent spends a cent — even though the token is too new to be indexed anywhere else. Even USDC comes back
`CAUTION`, not `SAFE`, because the issuer can still freeze your balance — the verdict tells you the truth, not
a marketing label.

## Tools

**Screening**
- `scan_token` — full safety report in one call: authority, Token-2022 traps, honeypot, liquidity & holder concentration → SAFE/CAUTION/DANGER + a 0–100 score
- `is_safe` — quick yes/no gate: one boolean before you trade
- `verify_token_safety` — on-chain audit: mint/freeze authority + Token-2022 traps + live market
- `check_authorities` — mint / freeze authority and extension detection
- `simulate_sell` — can the token actually be sold? (honeypot check)
- `simulate_trade` — full round-trip (buy then sell back): real entry/exit cost & round-trip loss %
- `check_liquidity` — DEX liquidity, 24h volume, age, buys/sells
- `holders_breakdown` — top-holder concentration (dump risk)
- `token_age` — freshness + real trading activity
- `rug_forecast` — heuristic rug ETA: probability + urgency window + factors
- `scammer_dna` — intent score (0–100): how much the token's structure looks like a deliberate scam
- `check_deployer` — the wallets that hold power over the token
- `compare_tokens` — rank a basket of tokens safest-first
- `batch_scan` — scan up to 10 tokens at once, one report each

**Execution**
- `execute_safe_swap` — re-screens the mint, then builds a Jito-tipped Jupiter swap (unsigned); refuses tokens that scan DANGER

## Connect

**Remote (Streamable HTTP)** — no install, point your agent at:

```
https://web-production-58d585.up.railway.app/mcp
```

Listed on the [official MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.MrWizardlyLoaf/rugcheck-ai`.

**Self-host:**

```bash
pip install -r requirements.txt
SOLANA_RPC=<your-rpc-url> python server.py
```

### Add it to your agent

**Cline / Claude Dev (VS Code)** — in `cline_mcp_settings.json`:

```json
{ "mcpServers": { "rugcheck-ai": { "url": "https://web-production-58d585.up.railway.app/mcp" } } }
```

**Claude Desktop** — in `claude_desktop_config.json`:

```json
{ "mcpServers": { "rugcheck-ai": { "command": "npx", "args": ["-y", "mcp-remote", "https://web-production-58d585.up.railway.app/mcp"] } } }
```

**Cursor** — Settings → MCP → Add → Streamable HTTP, then paste the endpoint URL.

**Any MCP client** — it's a standard Streamable HTTP MCP server; point your client at the `/mcp` endpoint and the 15 tools appear.

## Why

Most agents trade Solana tokens blind. RugCheck AI calls `getAccountInfo` on the mint and reads the
authorities and Token-2022 extensions itself, so you get a real verdict on a fresh launch instead of
`unknown` — and a live mint or freeze authority is flagged before you buy, not after.

## Use it when

Your agent needs to answer, before it spends a cent:

- *Is this Solana token safe to buy — or is it a rug pull?*
- *Is this a honeypot — will I actually be able to sell after I buy?*
- *Does the mint have an active freeze / mint authority that can trap or dilute me?*
- *Is there a hidden Token-2022 trap (permanent delegate, transfer hook) that can drain me?*
- *Pre-trade screening / token due-diligence for an autonomous trading agent.*

Built for AI trading agents, snipers and bots that buy SPL / Token-2022 tokens and need a fast
on-chain rug check before entering — then a screened Jupiter route once a token clears.

## FAQ

**How do I check if a Solana token is safe to buy?**
Call `scan_token(mint)` — one call returns a SAFE / CAUTION / DANGER verdict covering mint/freeze
authority, Token-2022 traps, honeypot (sellability), liquidity and holder concentration, plus a
0–100 safety score.

**How do I detect a honeypot before buying?**
`simulate_sell(mint)` checks whether a live sell route exists — a token with no route is effectively
a honeypot even when nothing on-chain formally blocks selling.

**How do I check holder concentration / whale dump risk?**
`holders_breakdown(mint)` reports the largest wallets and what share of supply they control — high
concentration means one holder can crash the price on you.

**How do I know if a token is a rug pull?**
`rug_forecast(mint)` gives a heuristic rug probability and urgency window from real signals
(authority, Token-2022 traps, concentration, sell pressure, age). `check_authorities` and
`check_deployer` show exactly who holds power over the token.

**Does it work on fresh / newly launched tokens?**
Yes — it reads the mint directly on-chain (`getAccountInfo`), so you get a real verdict on a token
too new to be indexed elsewhere. `token_age` shows freshness and real trading activity.

**Does it touch my wallet or sign anything?**
No. Screening is read-only; `execute_safe_swap` only builds an UNSIGNED transaction for you to sign —
the server never holds keys, never signs, never sends.

**Is it free? Do I need an API key?**
Remote server, no install, no API key. Point your agent at the endpoint and call the tools.

## Status

v1.2.0 — working, actively developed, CI-tested. Open source, auditable — the screening tools are
read-only (`getAccountInfo`); `execute_safe_swap` only builds an unsigned transaction for you to sign.

---

*MIT licensed. Self-hostable. Built for Solana trading agents.*
