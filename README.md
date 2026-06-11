# 🛡️ SolGuard — On-chain Token Safety for Solana AI Agents

![version](https://img.shields.io/badge/version-1.0.1-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![MCP](https://img.shields.io/badge/MCP-Registry-7c3aed)
![python](https://img.shields.io/badge/python-3.12-3776ab)
![transport](https://img.shields.io/badge/transport-Streamable_HTTP-success)

A lightweight MCP server that reads a Solana token's mint **directly from the chain** to screen for
the common rug & honeypot traps **before** your agent trades — active mint/freeze authority and
dangerous Token-2022 extensions (permanent delegate, transfer hooks, non-transferable, pausable) —
then executes the buy through an MEV-protected route.

## Tools

- `verify_token_safety` — on-chain audit: mint/freeze authority + Token-2022 traps
- `check_authorities` — mint / freeze authority and extension detection
- `simulate_sell` — can the token actually be sold? (on-chain block check)
- `execute_safe_swap` — gas-optimized, MEV-protected swap execution

## Connect

**Remote (Streamable HTTP)** — no install, point your agent at:

```
https://web-production-58d585.up.railway.app/mcp
```

Listed on the [official MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.MrWizardlyLoaf/solguard`.

**Self-host:**

```bash
pip install -r requirements.txt
SOLANA_RPC=<your-rpc-url> python server.py
```

## Why

Most agents trade Solana tokens blind. SolGuard calls `getAccountInfo` on the mint and reads the
authorities and Token-2022 extensions itself, so you get a real verdict on a fresh launch instead of
`unknown` — and a live mint or freeze authority is flagged before you buy, not after.

## Status

Stable (v1.0.1). Open source, auditable — the screening tools are read-only (`getAccountInfo`).

---

*MIT licensed. Self-hostable. Built for Solana trading agents.*
