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

- `verify_token_safety(mint)` — on-chain rug/honeypot audit; returns a SAFE/CAUTION/DANGER verdict
- `check_authorities(mint)` — mint/freeze authority + Token-2022 trap report
- `simulate_sell(mint)` — honeypot / sellability check (can you actually sell it back?)
- `execute_safe_swap(mint, wallet, amount_usd)` — re-screens, then returns an unsigned swap to sign

## Self-host (optional)

```bash
pip install -r requirements.txt
SOLANA_RPC=<your-solana-rpc-url> python server.py
```

The screening tools are read-only (`getAccountInfo`); `execute_safe_swap` only builds an unsigned
transaction for the agent to sign — the server never holds keys, never signs, never sends.
