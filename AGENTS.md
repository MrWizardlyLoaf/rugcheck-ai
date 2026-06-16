# RugCheck AI — agent guide

On-chain token-safety MCP for Solana. Screen a token for rug/honeypot traps before trading, then
execute the buy — re-screened, and routed through Jupiter with a small Jito tip for inclusion. The
execution tool returns an unsigned transaction; you sign it, the server never holds keys.

## Connect (no install)

Remote MCP endpoint (Streamable HTTP):

```
https://web-production-58d585.up.railway.app/mcp
```

Listed on the official MCP Registry as `io.github.MrWizardlyLoaf/rugcheck-ai`.

## Tools

- `scan_token(mint)` — full safety report in one call (verdict, 0–100 score, all risks)
- `is_safe(mint)` — quick yes/no gate: one boolean before trading
- `verify_token_safety(mint)` — on-chain audit: mint/freeze authority + Token-2022 traps
- `check_authorities(mint)` — authority + extension detection
- `simulate_sell(mint)` — can the token be sold? (honeypot check)
- `simulate_trade(mint, amount_usd)` — round-trip buy→sell: real entry/exit cost & loss %
- `check_liquidity(mint)` — DEX liquidity, 24h volume, pair age
- `holders_breakdown(mint)` — top-holder concentration (dump risk)
- `token_age(mint)` — freshness + real trading activity
- `rug_forecast(mint)` — heuristic rug probability + urgency window
- `scammer_dna(mint)` — intent score (0–100) from structural scam signals
- `check_deployer(mint)` — the wallets holding power over the token
- `compare_tokens(mints)` — rank a basket of tokens safest-first
- `batch_scan(mints)` — scan up to 10 tokens at once, one report each
- `execute_safe_swap(mint, wallet, amount_usd)` — re-screens, returns an unsigned USDC→token swap to sign

## Source & stack

Built with **Python** (FastMCP). Entry point: **`server.py`**. The screening tools are read-only —
they call Solana `getAccountInfo` and never touch your keys.

## Self-host

```bash
pip install -r requirements.txt
SOLANA_RPC=<your-rpc-url> python server.py
```
