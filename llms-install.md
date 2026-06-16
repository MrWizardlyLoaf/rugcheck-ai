# RugCheck AI — install guide for Cline / MCP clients

RugCheck AI is a **remote** MCP server (Streamable HTTP). No install, no build step, no API key —
the server is hosted and ready.

## Connect (remote — recommended)

Add this to your MCP client configuration:

```json
{
  "mcpServers": {
    "rugcheck-ai": {
      "url": "https://web-production-58d585.up.railway.app/mcp"
    }
  }
}
```

That's the whole setup. Once connected, these tools are available:

- `scan_token(mint)` — full safety report in one call (verdict, 0–100 score, all risks)
- `is_safe(mint)` — quick yes/no gate: one boolean before trading
- `verify_token_safety(mint)` — on-chain rug/honeypot audit; SAFE/CAUTION/DANGER verdict
- `check_authorities(mint)` — mint/freeze authority + Token-2022 trap report
- `simulate_sell(mint)` — honeypot / sellability check (can you actually sell it back?)
- `simulate_trade(mint, amount_usd)` — round-trip buy→sell estimate: entry/exit cost & loss %
- `check_liquidity(mint)` — DEX liquidity, 24h volume, pair age, buy/sell counts
- `holders_breakdown(mint)` — top-holder concentration (dump risk)
- `token_age(mint)` — freshness + real trading activity
- `rug_forecast(mint)` — heuristic rug probability + urgency window
- `scammer_dna(mint)` — intent score (0–100) from structural scam signals
- `check_deployer(mint)` — the wallets holding power over the token
- `compare_tokens(mints)` — rank a basket of tokens safest-first
- `batch_scan(mints)` — scan up to 10 tokens at once, one report each
- `execute_safe_swap(mint, wallet, amount_usd)` — re-screens, then returns an unsigned USDC→token swap to sign

## Self-host (optional)

```bash
pip install -r requirements.txt
SOLANA_RPC=<your-solana-rpc-url> python server.py
```

The screening tools are read-only (`getAccountInfo`); `execute_safe_swap` only builds an unsigned
transaction for the agent to sign — the server never holds keys, never signs, never sends.
