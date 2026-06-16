# 🛡️ RugCheck AI — On-chain Token Safety for Solana AI Agents

![version](https://img.shields.io/badge/version-1.0.1-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![MCP](https://img.shields.io/badge/MCP-Registry-7c3aed)
![python](https://img.shields.io/badge/python-3.12-3776ab)
![transport](https://img.shields.io/badge/transport-Streamable_HTTP-success)
![CI](https://github.com/MrWizardlyLoaf/rugcheck-ai/actions/workflows/ci.yml/badge.svg)

A lightweight MCP server that reads a Solana token's mint **directly from the chain** to screen for
the common rug & honeypot traps **before** your agent trades — active mint/freeze authority and
dangerous Token-2022 extensions (permanent delegate, transfer hooks, non-transferable, pausable) —
then, for tokens that pass, builds the buy as an **unsigned** Jupiter transaction carrying a Jito tip
(bundle inclusion + revert protection) for MEV-resistance. You sign it; the server never holds keys.

## Tools

- `verify_token_safety` — on-chain audit: mint/freeze authority + Token-2022 traps
- `check_authorities` — mint / freeze authority and extension detection
- `simulate_sell` — can the token actually be sold? (on-chain block check)
- `execute_safe_swap` — re-screens the mint, then builds a Jito-tipped (MEV-resistant) Jupiter swap (unsigned)

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
on-chain rug check before entering — then a screened, MEV-resistant route once a token clears.

## Status

v1.0.1 — working, actively developed, CI-tested. Open source, auditable — the screening tools are
read-only (`getAccountInfo`); `execute_safe_swap` only builds an unsigned transaction for you to sign.

---

*MIT licensed. Self-hostable. Built for Solana trading agents.*
