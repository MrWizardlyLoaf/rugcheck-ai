# RugCheck AI — agent guide

On-chain token-safety MCP for Solana. Screen a token for rug/honeypot traps before trading, then
screen the output token, then build the buy as a Jupiter swap (MEV-protected via a Jito tip), returned unsigned for you to sign.

## Connect (no install)

Remote MCP endpoint (Streamable HTTP):

```
https://web-production-58d585.up.railway.app/mcp
```

Listed on the official MCP Registry as `io.github.MrWizardlyLoaf/rugcheck-ai`.

## Tools

- `verify_token_safety(mint)` — on-chain audit: mint/freeze authority + Token-2022 traps
- `check_authorities(mint)` — authority + extension detection
- `simulate_sell(mint)` — can the token be sold? (honeypot check)
- `execute_safe_swap(input_mint, output_mint, wallet, amount)` — MEV-protected swap

## Source & stack

Built with **Python** (FastMCP). Entry point: **`server.py`**. The screening tools are read-only —
they call Solana `getAccountInfo` and never touch your keys.

## Self-host

```bash
pip install -r requirements.txt
SOLANA_RPC=<your-rpc-url> python server.py
```
