# RugCheck AI — examples

Quick recipes for screening Solana tokens before trading. Connect remotely (no install):

```json
{ "mcpServers": { "rugcheck-ai": { "url": "https://web-production-58d585.up.railway.app/mcp" } } }
```

## 1. Full safety scan before buying

One call returns the whole picture — authority, Token-2022 traps, honeypot, liquidity, concentration:

```
scan_token("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")   # USDC — representative snapshot, live values vary
→ { verdict: "CAUTION", safety_score: 70, sellable: true,
    risks: ["mint authority active — supply can be inflated",
            "freeze authority active — your wallet can be frozen"],
    mint_authority: "BJE5MM…ruG", freeze_authority: "7dGbd2…rar",
    liquidity_usd: 3873064.0, volume_24h: 1449969.0 }
```

Gate your buy on `verdict`: do not buy on `DANGER`. For a one-line boolean gate instead, use `is_safe`:

```
is_safe("<mint>")  → { safe: true|false, verdict: "SAFE", safety_score: 100, reason: "..." }
```

## 2. Honeypot check (can I actually sell?)

```
simulate_sell("<mint>")  → { sellable: true|false, verdict: "..." }
```

A token with no live sell route is effectively a honeypot even if nothing on-chain formally blocks it.
For the real cost of entering *and* exiting at your size, simulate the full round-trip:

```
simulate_trade("<mint>", 100)
→ { buyable: true, sellable: true, exit_usd: 99.8, round_trip_loss_pct: 0.2 }   # honeypot → sellable:false
```

## 3. Rug-pull forecast

```
rug_forecast("<mint>")
→ { rug_probability_pct: 0-100, window: "imminent|hours|days|low", factors: ["...", ...] }
```

## 4. Holder concentration / whale dump risk

```
holders_breakdown("<mint>")  → { top_holder_pct: 13.7, top5_holder_pct: 35.2, top_holders: [...] }
```

## 5. Compare a basket, pick the safest

```
compare_tokens(["<mintA>", "<mintB>", "<mintC>"])  → reports ranked safest-first
```

## 6. Buy a screened token (you sign)

```
execute_safe_swap("<mint>", "<your-wallet>", 100)
→ { route: "safety-verified", transaction: "<base64 UNSIGNED tx>" }
```

`execute_safe_swap` re-screens the mint and returns an **unsigned** transaction — you sign it; the
server never holds keys.
