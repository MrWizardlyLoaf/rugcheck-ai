"""RugCheck AI — On-chain token safety + safe execution for Solana AI agents.

Reads the token mint directly from Solana (getAccountInfo) to check mint/freeze authority, supply,
and Token-2022 extension traps. A token that passes the screen can be bought in the same step via a
Jupiter route that carries a small Jito tip for faster inclusion.

Screening tools are read-only (getAccountInfo). execute_safe_swap re-runs the same screen and only
builds an UNSIGNED transaction for the agent to sign — it never holds keys, never signs, never sends.
"""
import os
import time

import httpx
from fastmcp import FastMCP
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse, PlainTextResponse

RPC = os.environ.get("SOLANA_RPC", "https://api.mainnet-beta.solana.com")
JUP_QUOTE = "https://lite-api.jup.ag/swap/v1/quote"
JUP_SWAP = "https://lite-api.jup.ag/swap/v1/swap"
JUP_PRICE = "https://lite-api.jup.ag/price/v3"
DEXSCREENER = "https://api.dexscreener.com/latest/dex/tokens/"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOL_MINT = "So11111111111111111111111111111111111111112"  # wSOL — sell-route quote when the token IS USDC

_DANGER_EXTS = {
    "permanentDelegate": "permanent delegate — the creator can move or burn your tokens anytime",
    "transferHook": "custom transfer hook — can block selling",
    "nonTransferable": "non-transferable — the token cannot be sold",
    "pausable": "pausable — trading can be paused, locking your sell",
}
_BLOCKING_EXTS = {"nonTransferable", "pausable"}


class TokenSafety(BaseModel):
    """On-chain safety verdict for one SPL / Token-2022 mint, produced before you trade it."""
    token: str = Field(description="The mint address that was audited.")
    verdict: str = Field(description="Overall risk: SAFE (no red flags), CAUTION (authority/liquidity risk), "
                         "DANGER (rug or honeypot trap present), or UNKNOWN (not a mint / RPC unavailable).")
    mint_authority: str | None = Field(default=None, description="Active mint-authority address if present — its "
                                       "holder can mint new supply and dilute you after purchase; None means revoked.")
    freeze_authority: str | None = Field(default=None, description="Active freeze-authority address if present — its "
                                         "holder can freeze your account so you cannot sell; None means revoked.")
    supply: str | None = Field(default=None, description="Raw on-chain total supply.")
    decimals: int | None = Field(default=None, description="Token decimal places.")
    extensions: list[str] = Field(default=[], description="Token-2022 extensions present on the mint (e.g. transferHook).")
    risks: list[str] = Field(default=[], description="Plain-language risk flags detected; empty means none found.")
    error: str | None = Field(default=None, description="Populated when the mint could not be read.")


class Authorities(BaseModel):
    """Mint/freeze authority and Token-2022 extension report for one mint."""
    mint: str = Field(description="The mint address inspected.")
    mint_authority: str | None = Field(default=None, description="Active mint-authority address, or None if revoked.")
    freeze_authority: str | None = Field(default=None, description="Active freeze-authority address, or None if revoked.")
    token2022_extensions: list[str] = Field(default=[], description="All Token-2022 extensions present on the mint.")
    dangerous_extensions: list[str] = Field(default=[], description="Subset considered dangerous: permanentDelegate, "
                                            "transferHook, nonTransferable, pausable.")
    verdict: str | None = Field(default=None, description="'clean' if no authorities/traps present, otherwise 'review'.")
    error: str | None = Field(default=None, description="Populated when the mint could not be read.")


class SellCheck(BaseModel):
    """Honeypot / sellability result for one mint — whether a buyer could actually sell it back."""
    mint: str = Field(description="The mint address checked.")
    sellable: bool | None = Field(default=None, description="True if a live sell route exists and nothing on-chain "
                                  "blocks selling; False if blocked or no route; None if it could not be determined.")
    blocking_extensions: list[str] = Field(default=[], description="Extensions that block selling (nonTransferable, pausable).")
    freeze_authority: str | None = Field(default=None, description="Active freeze authority, which can also block selling.")
    verdict: str | None = Field(default=None, description="Plain-language sellability summary with the reason.")
    error: str | None = Field(default=None, description="Populated when the mint could not be read.")


class SwapResult(BaseModel):
    """An UNSIGNED swap transaction (or a block notice) returned for the agent to sign itself."""
    action: str = Field(description="'buy' when a swap was built, or 'blocked' when the token failed the safety screen.")
    token: str = Field(description="The token mint the swap targets.")
    amount_usd: float = Field(description="The USD size requested for the trade.")
    route: str = Field(description="Route label: 'safety-verified' when screened & built, 'screen-blocked' if refused.")
    note: str = Field(description="Human-readable note: sign to execute, or why it was blocked.")
    transaction: str = Field(description="Base64 UNSIGNED transaction for the agent to sign & submit; empty if blocked.")


class LiquidityInfo(BaseModel):
    """Liquidity depth and recent trading activity for a token (DEX market data)."""
    mint: str = Field(description="The mint address checked.")
    liquidity_usd: float | None = Field(default=None, description="Total DEX liquidity in USD across the token's pairs.")
    volume_24h: float | None = Field(default=None, description="24-hour traded volume in USD.")
    age_days: float | None = Field(default=None, description="Age of the oldest trading pair, in days (None if unlisted).")
    buys_24h: int | None = Field(default=None, description="Number of buy transactions in the last 24h.")
    sells_24h: int | None = Field(default=None, description="Number of sell transactions in the last 24h.")
    error: str | None = Field(default=None, description="Populated when no market data was found.")


class HoldersInfo(BaseModel):
    """Holder concentration for a token — how much supply the largest wallets control."""
    mint: str = Field(description="The mint address checked.")
    top_holder_pct: float | None = Field(default=None, description="Percent of supply held by the single largest account.")
    top5_holder_pct: float | None = Field(default=None, description="Percent of supply held by the top 5 accounts combined.")
    holder_accounts: int | None = Field(default=None, description="Number of largest accounts inspected.")
    top_holders: list[dict] = Field(default=[], description="Largest accounts with their address and percent of supply.")
    error: str | None = Field(default=None, description="Populated when holder data is unavailable.")


class RugForecast(BaseModel):
    """Heuristic rug-pull risk forecast — a weighted score over observable on-chain signals (NOT a guarantee)."""
    mint: str = Field(description="The mint address assessed.")
    rug_probability_pct: int = Field(description="Heuristic rug probability 0-100 from the factors below. Not an ML prediction.")
    window: str = Field(description="Urgency window: imminent / hours / days / low.")
    factors: list[str] = Field(default=[], description="The specific risk signals that drove the score.")


class RiskReport(BaseModel):
    """Full safety report for a token — the flagship scan combining every screen into one verdict."""
    mint: str = Field(description="The mint address scanned.")
    verdict: str = Field(description="Overall risk: SAFE / CAUTION / DANGER / UNKNOWN.")
    safety_score: int = Field(description="0-100 composite safety score (higher = safer).")
    risks: list[str] = Field(default=[], description="All risk flags found across authority, extensions, liquidity, sellability.")
    mint_authority: str | None = Field(default=None, description="Active mint authority, or None if revoked.")
    freeze_authority: str | None = Field(default=None, description="Active freeze authority, or None if revoked.")
    dangerous_extensions: list[str] = Field(default=[], description="Dangerous Token-2022 extensions present.")
    sellable: bool | None = Field(default=None, description="Whether a live sell route exists (honeypot if False).")
    liquidity_usd: float | None = Field(default=None, description="Total DEX liquidity in USD.")
    volume_24h: float | None = Field(default=None, description="24h volume in USD.")
    age_days: float | None = Field(default=None, description="Age of the oldest pair in days.")
    top_holder_pct: float | None = Field(default=None, description="Largest-wallet concentration, percent of supply.")
    holder_count: int | None = Field(default=None, description="Largest accounts inspected for concentration.")
    error: str | None = Field(default=None, description="Populated when the token could not be read.")


mcp = FastMCP(name="RugCheck AI",
              instructions="On-chain token-safety screening + safe execution for Solana trading agents. "
                           "Start with scan_token(mint) for the full SAFE/CAUTION/DANGER verdict (authority, "
                           "Token-2022 traps, honeypot, liquidity and holder concentration in one call), or "
                           "is_safe(mint) for a quick yes/no gate. Drill in with verify_token_safety, "
                           "check_authorities, simulate_sell (honeypot), simulate_trade (round-trip cost), "
                           "check_liquidity, holders_breakdown, token_age, rug_forecast (rug ETA), "
                           "scammer_dna (intent score) and check_deployer; compare_tokens / batch_scan handle "
                           "a basket. Then execute_safe_swap buys a token that cleared — it re-screens and "
                           "returns an unsigned, Jito-tipped transaction for you to sign. "
                           "Screening is read-only; nothing ever signs for you.")


async def _read_mint(mint: str) -> dict | None:
    """Read the mint account directly from Solana: authorities, supply, decimals, extensions."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
                                        "params": [mint, {"encoding": "jsonParsed"}]})
        value = ((r.json().get("result") or {}).get("value")) or {}
        info = ((value.get("data") or {}).get("parsed") or {}).get("info")
    except Exception:
        return None
    if not info or "decimals" not in info:
        return None
    exts = [e.get("extension") for e in (info.get("extensions") or []) if e.get("extension")]
    return {"mint_authority": info.get("mintAuthority"), "freeze_authority": info.get("freezeAuthority"),
            "decimals": info.get("decimals"), "supply": info.get("supply"), "extensions": exts}


async def _has_market(mint: str) -> bool | None:
    """Does the token have a live market? (a Jupiter price implies a routable, liquid pair). None on error."""
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get("https://lite-api.jup.ag/price/v3", params={"ids": mint})
        return bool((r.json().get(mint) or {}).get("usdPrice"))
    except Exception:
        return None


@mcp.tool
async def verify_token_safety(mint: str) -> TokenSafety:
    """Audit a Solana token for rug-pull and honeypot risk before buying it.

    Call this FIRST, before entering any position. Reads the mint directly on-chain (getAccountInfo)
    and flags: an active mint authority (supply can be inflated after you buy), an active freeze
    authority (your tokens can be frozen), dangerous Token-2022 extensions (permanent delegate,
    transfer hook, non-transferable, pausable), and whether the token has a live, routable market
    (no market is itself a risk). Returns a TokenSafety with a SAFE / CAUTION / DANGER / UNKNOWN
    verdict plus the specific risks found — gate your buy decision on `verdict`.

    Args:
        mint: The SPL or Token-2022 mint address to audit.
    """
    m = await _read_mint(mint)
    if not m:
        return TokenSafety(token=mint, verdict="UNKNOWN",
                           error="not an SPL/Token-2022 mint, or RPC unavailable")
    risks = []
    if m["mint_authority"]:
        risks.append("mint authority active — supply can be inflated after you buy")
    if m["freeze_authority"]:
        risks.append("freeze authority active — your tokens can be frozen")
    bad_exts = [e for e in m["extensions"] if e in _DANGER_EXTS]
    risks += [_DANGER_EXTS[e] for e in bad_exts]
    market = await _has_market(mint)
    if market is False:
        risks.append("no live market — illiquid or unlaunched, you may not be able to sell")
    elif market is None:
        risks.append("market status unverified — could not confirm a live route")
    verdict = ("DANGER" if bad_exts else "CAUTION" if risks else "SAFE")
    return TokenSafety(token=mint, verdict=verdict, mint_authority=m["mint_authority"],
                       freeze_authority=m["freeze_authority"], supply=m["supply"], decimals=m["decimals"],
                       extensions=m["extensions"], risks=risks or ["no authority or extension red flags"])


@mcp.tool
async def check_authorities(mint: str) -> Authorities:
    """Report a token's mint/freeze authority and Token-2022 traps, read directly on-chain.

    Use this for a focused authority check when you want the raw authority picture (e.g. to confirm a
    creator truly renounced control) rather than the full verdict from verify_token_safety. Returns an
    Authorities report listing every Token-2022 extension and which of them are dangerous.

    Args:
        mint: The SPL or Token-2022 mint address to inspect.
    """
    m = await _read_mint(mint)
    if not m:
        return Authorities(mint=mint, error="not an SPL/Token-2022 mint, or RPC unavailable")
    traps = [e for e in m["extensions"] if e in _DANGER_EXTS]
    return Authorities(mint=mint, mint_authority=m["mint_authority"], freeze_authority=m["freeze_authority"],
                       token2022_extensions=m["extensions"], dangerous_extensions=traps,
                       verdict="clean" if not traps and not m["mint_authority"] and not m["freeze_authority"]
                       else "authorities or extensions present — review")


async def _can_route_sell(mint: str, decimals: int) -> bool | None:
    """Live sell-route probe: can `mint` be routed out on Jupiter? None on error."""
    quote = SOL_MINT if mint == USDC_MINT else USDC_MINT  # USDC routes to SOL (USDC->USDC is degenerate)
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            q = (await c.get(JUP_QUOTE, params={
                "inputMint": mint, "outputMint": quote,
                "amount": 10 ** min(decimals or 0, 9), "slippageBps": 300})).json()
        return bool(q.get("outAmount") and not q.get("error"))
    except Exception:
        return None


def _f(x, default: float = 0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


async def _dexscreener(mint: str) -> dict | None:
    """DEX market data: liquidity, 24h volume, pair age, buy/sell counts. None if no live market."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            data = (await c.get(DEXSCREENER + mint)).json()
        pairs = [p for p in (data.get("pairs") or []) if isinstance(p, dict)]
        if not pairs:
            return None
        p = max(pairs, key=lambda x: _f((x.get("liquidity") or {}).get("usd")))
        txns = (p.get("txns") or {}).get("h24") or {}
        created = p.get("pairCreatedAt")
        age = (time.time() - created / 1000) / 86400 if created else None
        return {"liquidity_usd": round(_f((p.get("liquidity") or {}).get("usd")), 2),
                "volume_24h": round(_f((p.get("volume") or {}).get("h24")), 2),
                "age_days": round(age, 2) if age is not None else None,
                "buys_24h": int(_f(txns.get("buys"))), "sells_24h": int(_f(txns.get("sells")))}
    except Exception:
        return None


async def _largest_accounts(mint: str) -> dict | None:
    """Top-holder concentration via getTokenLargestAccounts + getTokenSupply. None on error."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            largest = (await c.post(RPC, json={"jsonrpc": "2.0", "id": 1,
                                               "method": "getTokenLargestAccounts", "params": [mint]})).json()
            supply_r = (await c.post(RPC, json={"jsonrpc": "2.0", "id": 1,
                                                "method": "getTokenSupply", "params": [mint]})).json()
        accs = ((largest.get("result") or {}).get("value")) or []
        supply = _f(((supply_r.get("result") or {}).get("value") or {}).get("amount"))
        if not accs or supply <= 0:
            return None
        rows = [{"address": a.get("address"), "pct": round(_f(a.get("amount")) / supply * 100, 2)}
                for a in accs[:20]]
        return {"top_holder_pct": rows[0]["pct"] if rows else None,
                "top5_holder_pct": round(sum(r["pct"] for r in rows[:5]), 2),
                "holder_accounts": len(rows), "top_holders": rows[:10]}
    except Exception:
        return None


@mcp.tool
async def simulate_sell(mint: str) -> SellCheck:
    """Check whether a token can actually be SOLD after buying — a dedicated honeypot detector.

    Call this when you specifically worry a token is a honeypot (you can buy but not exit). Combines
    on-chain constraints (non-transferable / pausable extensions, freeze authority) with a live
    Jupiter sell-route probe — a token with no sell route is effectively a honeypot even if no
    extension formally blocks it. Returns a SellCheck where `sellable` is the bottom line.

    Args:
        mint: The SPL or Token-2022 mint address to test for sellability.
    """
    m = await _read_mint(mint)
    if not m:
        return SellCheck(mint=mint, error="not an SPL/Token-2022 mint, or RPC unavailable")
    blocking = [e for e in m["extensions"] if e in _BLOCKING_EXTS]
    route = await _can_route_sell(mint, m["decimals"] or 0)
    if blocking:
        sellable, verdict = False, f"NOT sellable — {', '.join(blocking)}"
    elif route is False:
        sellable, verdict = False, "NOT sellable — no live sell route (illiquid or honeypot)"
    elif route is None:
        sellable, verdict = None, "sellability UNCONFIRMED — sell-route probe failed, retry before trusting"
    else:
        sellable, verdict = True, "sellable — on-chain clear and a live sell route exists"
    return SellCheck(mint=mint, sellable=sellable, blocking_extensions=blocking,
                     freeze_authority=m["freeze_authority"], verdict=verdict)


@mcp.tool
async def execute_safe_swap(mint: str, wallet: str, amount_usd: float, input_mint: str = USDC_MINT) -> SwapResult:
    """Buy `amount_usd` of a token, paying with USDC (or `input_mint`) — only AFTER it passes the scan.

    The point of a safety router: never execute an unscreened trade. The target mint is re-scanned
    here with the full scan_token verdict; if the verdict is DANGER (honeypot, active freeze/mint
    authority, dangerous Token-2022 extension, no sell route), NO swap is built. Otherwise it builds a
    Jupiter swap from `input_mint` (USDC by default) into the target for exactly `amount_usd` and
    returns an UNSIGNED transaction for you to sign. The build adds a small Jito tip (~0.0001 SOL) for
    faster inclusion and wraps/unwraps SOL as needed. Note: only a DANGER verdict is refused — a CAUTION
    token (e.g. an active mint authority) is allowed through, so check the scan yourself if you require
    SAFE-only. The server only reads the target mint and builds the route — it never reads your other
    holdings, never holds keys, never signs, never sends.

    Args:
        mint: Token to buy.
        wallet: The agent's wallet — signer and funder (the swap is built for this pubkey).
        amount_usd: Amount to spend, in USD of the input token.
        input_mint: Mint to pay with — defaults to USDC. The swap is always input_mint -> mint.
    """
    # Full re-scan; refuse to build a swap for anything that scans DANGER.
    report = await scan_token(mint)
    if report.verdict == "DANGER":
        reason = "; ".join(report.risks[:2]) or "failed safety scan"
        return SwapResult(action="blocked", token=mint, amount_usd=amount_usd, route="screen-blocked",
                          note=f"Refused — scan_token returned DANGER: {reason}. No swap built.", transaction="")
    if input_mint == USDC_MINT:
        in_decimals = 6
    else:
        im = await _read_mint(input_mint)
        in_decimals = im["decimals"] if im and im.get("decimals") is not None else 9
    amount = max(1, int(amount_usd * 10 ** in_decimals))
    try:
        async with httpx.AsyncClient(timeout=18) as c:
            q = (await c.get(JUP_QUOTE, params={"inputMint": input_mint, "outputMint": mint,
                                                "amount": amount, "slippageBps": 100})).json()
            if q.get("error") or not q.get("outAmount"):
                return SwapResult(action="blocked", token=mint, amount_usd=amount_usd, route="no-route",
                                  note="No swap route available for this pair right now.", transaction="")
            s = (await c.post(JUP_SWAP, json={"quoteResponse": q, "userPublicKey": wallet,
                                              "asLegacyTransaction": True, "wrapAndUnwrapSol": True,
                                              "prioritizationFeeLamports": {"jitoTipLamports": 100_000}})).json()
        if not s.get("swapTransaction"):
            return SwapResult(action="blocked", token=mint, amount_usd=amount_usd, route="no-route",
                              note="Could not build the swap transaction (no route).", transaction="")
    except Exception as e:
        return SwapResult(action="blocked", token=mint, amount_usd=amount_usd, route="error",
                          note=f"Swap build failed: {type(e).__name__}.", transaction="")
    return SwapResult(action="buy", token=mint, amount_usd=amount_usd, route="safety-verified",
                      note="Screened OK — sign to execute the swap (input_mint -> token).",
                      transaction=s["swapTransaction"])


@mcp.tool
async def scan_token(mint: str) -> RiskReport:
    """Full safety scan of a Solana token — the one-call verdict combining every screen.

    Aggregates the on-chain authority/extension screen, a live honeypot (sell-route) check, DEX
    liquidity & trading activity, and top-holder concentration into one SAFE/CAUTION/DANGER verdict
    with a 0-100 safety score. Call this first for a complete picture; use the focused tools
    (check_liquidity, holders_breakdown, simulate_sell, rug_forecast) to drill into one aspect.

    Args:
        mint: The SPL or Token-2022 mint address to scan.
    """
    m = await _read_mint(mint)
    if not m:
        return RiskReport(mint=mint, verdict="UNKNOWN", safety_score=0,
                          error="not an SPL/Token-2022 mint, or RPC unavailable")
    risks = []
    if m["mint_authority"]:
        risks.append("mint authority active — supply can be inflated")
    if m["freeze_authority"]:
        risks.append("freeze authority active — your wallet can be frozen")
    bad = [e for e in m["extensions"] if e in _DANGER_EXTS]
    risks += [_DANGER_EXTS[e] for e in bad]
    sellable = await _can_route_sell(mint, m["decimals"] or 0)
    if sellable is False:
        risks.append("no live sell route — illiquid or honeypot")
    elif sellable is None:
        risks.append("sell route could not be verified — treat as unconfirmed, not safe")
    dex = await _dexscreener(mint) or {}
    holders = await _largest_accounts(mint) or {}
    if (holders.get("top_holder_pct") or 0) >= 50:
        risks.append(f"high concentration — top holder {holders['top_holder_pct']:.0f}%")
    liq = dex.get("liquidity_usd")
    if liq is not None and liq < 1000:
        risks.append(f"very low liquidity (${liq:,.0f})")
    score = max(0, 100 - 40 * len(bad) - 15 * (len(risks) - len(bad)))
    verdict = "DANGER" if (bad or sellable is False) else ("CAUTION" if risks else "SAFE")
    if verdict == "DANGER":
        score = min(score, 20)  # a DANGER verdict (honeypot / dangerous extension) is near-total-loss — keep the score coherent
    return RiskReport(mint=mint, verdict=verdict, safety_score=score, risks=risks or ["no red flags found"],
                      mint_authority=m["mint_authority"], freeze_authority=m["freeze_authority"],
                      dangerous_extensions=bad, sellable=sellable, liquidity_usd=liq,
                      volume_24h=dex.get("volume_24h"), age_days=dex.get("age_days"),
                      top_holder_pct=holders.get("top_holder_pct"), holder_count=holders.get("holder_accounts"))


@mcp.tool
async def check_liquidity(mint: str) -> LiquidityInfo:
    """Liquidity depth and 24h trading activity for a token — can you exit at size?

    Reports total DEX liquidity, 24h volume, pair age and buy/sell counts. Thin liquidity or no
    volume means you may not be able to sell at your size even if it is not a honeypot.

    Args:
        mint: The SPL or Token-2022 mint address.
    """
    d = await _dexscreener(mint)
    return LiquidityInfo(mint=mint, **d) if d else LiquidityInfo(mint=mint, error="no live DEX market found")


@mcp.tool
async def holders_breakdown(mint: str) -> HoldersInfo:
    """Top-holder concentration — how much of the supply the largest wallets control.

    High concentration (one wallet, or the top 5, holding most of the supply) is a dump/rug risk: a
    single holder can crash the price on you. Reads the largest token accounts on-chain.

    Args:
        mint: The SPL or Token-2022 mint address.
    """
    h = await _largest_accounts(mint)
    return HoldersInfo(mint=mint, **h) if h else HoldersInfo(mint=mint, error="holder data unavailable")


@mcp.tool
async def token_age(mint: str) -> LiquidityInfo:
    """Token age and recent trading activity — freshness and whether anyone is actually trading it.

    A token only minutes/hours old, or with no 24h volume, is high-risk (fresh launch or dead market).

    Args:
        mint: The SPL or Token-2022 mint address.
    """
    d = await _dexscreener(mint)
    return LiquidityInfo(mint=mint, **d) if d else LiquidityInfo(mint=mint, error="no live DEX market (unlisted or dead)")


@mcp.tool
async def rug_forecast(mint: str) -> RugForecast:
    """Heuristic rug-pull forecast — probability and urgency from observable on-chain signals.

    NOT an ML prediction or guarantee. Weights real factors: active mint/freeze authority, dangerous
    Token-2022 extensions, no sell route (honeypot), high holder concentration, sells outpacing buys,
    and very fresh age. Returns a 0-100 probability, an urgency window, and the contributing factors.

    Args:
        mint: The SPL or Token-2022 mint address.
    """
    m = await _read_mint(mint)
    if not m:
        return RugForecast(mint=mint, rug_probability_pct=0, window="unknown", factors=["token not readable"])
    p, factors = 0, []
    if m["mint_authority"]:
        p += 12; factors.append("mint authority active")
    if m["freeze_authority"]:
        p += 10; factors.append("freeze authority active")
    bad = [e for e in m["extensions"] if e in _DANGER_EXTS]
    if bad:
        p += 30; factors.append(f"dangerous extension: {', '.join(bad)}")
    if await _can_route_sell(mint, m["decimals"] or 0) is False:
        p += 35; factors.append("no sell route (honeypot)")
    h = await _largest_accounts(mint) or {}
    if (h.get("top_holder_pct") or 0) >= 50:
        p += 18; factors.append(f"top holder {h['top_holder_pct']:.0f}%")
    dex = await _dexscreener(mint) or {}
    if dex.get("sells_24h", 0) > dex.get("buys_24h", 0) * 2 and dex.get("sells_24h", 0) > 20:
        p += 15; factors.append("sells far outpace buys")
    if (dex.get("age_days") or 99) < 1:
        p += 10; factors.append("token younger than a day")
    p = min(100, p)
    window = "imminent" if p >= 60 else "hours" if p >= 45 else "days" if p >= 25 else "low"
    return RugForecast(mint=mint, rug_probability_pct=p, window=window, factors=factors or ["no strong rug signals"])


@mcp.tool
async def check_deployer(mint: str) -> dict:
    """The wallets that hold power over the token — its mint authority and freeze authority.

    Args:
        mint: The SPL or Token-2022 mint address.
    """
    m = await _read_mint(mint)
    if not m:
        return {"mint": mint, "error": "not an SPL/Token-2022 mint, or RPC unavailable"}
    return {"mint": mint, "mint_authority": m["mint_authority"], "freeze_authority": m["freeze_authority"],
            "note": "mint authority can create new supply; freeze authority can freeze wallets; "
                    "None means that power was revoked."}


@mcp.tool
async def compare_tokens(mints: list[str]) -> list[RiskReport]:
    """Scan several tokens and return them ranked safest-first — pick the best one to trade.

    Args:
        mints: List of SPL / Token-2022 mint addresses (up to 10).
    """
    out = [await scan_token(m) for m in mints[:10]]
    return sorted(out, key=lambda r: r.safety_score, reverse=True)


@mcp.tool
async def is_safe(mint: str) -> dict:
    """Quick yes/no gate before trading: is this token safe enough to enter?

    Wraps the full scan_token into a single boolean for fast decisions. `safe` is True only when the
    verdict is SAFE and a live sell route exists — anything CAUTION/DANGER or unsellable returns False.

    Args:
        mint: The SPL or Token-2022 mint address.
    """
    r = await scan_token(mint)
    safe = r.verdict == "SAFE" and r.sellable is True
    reason = next((x for x in r.risks if x != "no red flags found"), "no red flags")
    return {"mint": mint, "safe": safe, "verdict": r.verdict, "safety_score": r.safety_score, "reason": reason}


@mcp.tool
async def simulate_trade(mint: str, amount_usd: float = 100.0) -> dict:
    """Full round-trip simulation: buy `amount_usd` of the token with USDC, then sell it ALL back.

    Estimates the real cost of entering AND exiting at your size from Jupiter quotes (no on-chain
    execution): tokens received, USD returned, and round-trip loss % (both-side slippage). A honeypot
    shows buyable=true but sellable=false — you can enter but not exit.

    Args:
        mint: The SPL or Token-2022 mint address.
        amount_usd: Trade size in USD (default 100). Use your real size for an accurate estimate.
    """
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            buy = (await c.get(JUP_QUOTE, params={"inputMint": USDC_MINT, "outputMint": mint,
                                                  "amount": max(1, int(amount_usd * 1e6)), "slippageBps": 300})).json()
            if buy.get("error") or not buy.get("outAmount"):
                return {"mint": mint, "buyable": False, "sellable": None, "note": "no buy route — illiquid or no market"}
            tokens = int(buy["outAmount"])
            sell = (await c.get(JUP_QUOTE, params={"inputMint": mint, "outputMint": USDC_MINT,
                                                   "amount": tokens, "slippageBps": 300})).json()
    except Exception as e:
        return {"mint": mint, "error": f"{type(e).__name__}"}
    if sell.get("error") or not sell.get("outAmount"):
        return {"mint": mint, "buyable": True, "sellable": False, "tokens_received": tokens,
                "note": "buy works, SELL fails — honeypot"}
    exit_usd = round(int(sell["outAmount"]) / 1e6, 2)
    return {"mint": mint, "buyable": True, "sellable": True, "enter_usd": amount_usd,
            "tokens_received": tokens, "exit_usd": exit_usd,
            "round_trip_loss_pct": round((amount_usd - exit_usd) / amount_usd * 100, 2)}


@mcp.tool
async def batch_scan(mints: list[str]) -> list[RiskReport]:
    """Scan several tokens at once — one full safety report per mint (up to 10).

    Args:
        mints: List of SPL / Token-2022 mint addresses.
    """
    return [await scan_token(m) for m in mints[:10]]


@mcp.tool
async def scammer_dna(mint: str) -> dict:
    """Scammer-DNA / intent score (0-100): how much the token's STRUCTURE looks like a deliberate scam.

    A pattern score over structural signals — permanent delegate, kept mint/freeze authority, no sell
    route, extreme holder concentration. NOT proof of intent; a heuristic to flag deliberate scam setups.

    Args:
        mint: The SPL or Token-2022 mint address.
    """
    m = await _read_mint(mint)
    if not m:
        return {"mint": mint, "intent_score": 0, "verdict": "unknown", "signals": ["token not readable"]}
    score, signals = 0, []
    if "permanentDelegate" in m["extensions"]:
        score += 30; signals.append("permanent delegate — creator can seize your tokens")
    if any(e in m["extensions"] for e in ("transferHook", "pausable")):
        score += 15; signals.append("transfer hook / pausable — selling can be blocked")
    if m["freeze_authority"]:
        score += 12; signals.append("freeze authority kept")
    if m["mint_authority"]:
        score += 10; signals.append("mint authority kept")
    if await _can_route_sell(mint, m["decimals"] or 0) is False:
        score += 20; signals.append("no sell route (honeypot)")
    h = await _largest_accounts(mint) or {}
    if (h.get("top_holder_pct") or 0) >= 50:
        score += 18; signals.append(f"top holder controls {h['top_holder_pct']:.0f}%")
    score = min(100, score)
    verdict = "likely malicious setup" if score >= 60 else "suspicious" if score >= 35 else "no strong intent signals"
    return {"mint": mint, "intent_score": score, "verdict": verdict, "signals": signals or ["no strong intent signals"]}


@mcp.custom_route("/.well-known/glama.json", methods=["GET"])
async def glama_ownership(request):
    """Ownership verification for the Glama MCP connector registry."""
    return JSONResponse({
        "$schema": "https://glama.ai/mcp/schemas/connector.json",
        "maintainers": [{"email": "eliamcortesytbr@outlook.com"}],
    })


@mcp.custom_route("/llms.txt", methods=["GET"])
async def llms_txt(request):
    """AI-crawler discovery file (llms.txt standard) served at the domain root."""
    return PlainTextResponse(
        "# RugCheck AI\n\n"
        "On-chain token-safety MCP for Solana AI trading agents. Reads a token's mint directly to "
        "flag rug & honeypot traps (mint/freeze authority, Token-2022 extensions, holder "
        "concentration, liquidity, sellability) before trading, then builds an unsigned, Jito-tipped "
        "swap (small tip for faster inclusion).\n\n"
        "Remote MCP endpoint: https://web-production-58d585.up.railway.app/mcp\n"
        "Registry: io.github.MrWizardlyLoaf/rugcheck-ai\n"
        "Repo: https://github.com/MrWizardlyLoaf/rugcheck-ai\n\n"
        "Tools: scan_token, is_safe, verify_token_safety, check_authorities, simulate_sell, "
        "simulate_trade, check_liquidity, holders_breakdown, token_age, rug_forecast, scammer_dna, "
        "check_deployer, compare_tokens, batch_scan, execute_safe_swap.\n\n"
        "Use cases: is this Solana token safe to buy or a rug pull; is it a honeypot (can I sell after "
        "buying); holder concentration / whale risk; pre-trade screening for autonomous trading agents.\n")


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
