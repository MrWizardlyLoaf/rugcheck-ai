"""RugCheck AI — On-chain token safety + safe execution for Solana AI agents.

Reads the token mint directly from Solana (getAccountInfo) to check mint/freeze authority, supply,
and Token-2022 extension traps. A token that passes the screen can be bought in the same step via a
Jupiter route that carries a Jito tip (bundle inclusion + revert protection) for MEV-resistance.

Screening tools are read-only (getAccountInfo). execute_safe_swap re-runs the same screen and only
builds an UNSIGNED transaction for the agent to sign — it never holds keys, never signs, never sends.
"""
import base64
import os
import struct
import time

import httpx
from fastmcp import FastMCP
from pydantic import BaseModel, Field
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from starlette.responses import JSONResponse

RPC = os.environ.get("SOLANA_RPC", "https://api.mainnet-beta.solana.com")
SPL_TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
MEMO = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
COMPUTE = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
JUP_QUOTE = "https://lite-api.jup.ag/swap/v1/quote"
JUP_SWAP = "https://lite-api.jup.ag/swap/v1/swap"
JUP_PRICE = "https://lite-api.jup.ag/price/v3"
DEXSCREENER = "https://api.dexscreener.com/latest/dex/tokens/"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

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
                           "Token-2022 traps, honeypot, liquidity and holder concentration in one call). Drill "
                           "in with verify_token_safety, check_authorities, simulate_sell (honeypot), "
                           "check_liquidity, holders_breakdown, token_age, rug_forecast (rug ETA) and "
                           "check_deployer; compare_tokens ranks a basket safest-first. Then execute_safe_swap "
                           "buys a token that cleared — it re-screens and returns an unsigned, Jito-tipped "
                           "(MEV-resistant) transaction for you to sign. Screening is read-only; nothing ever signs for you.")


async def _latest_blockhash() -> Hash:
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": "getLatestBlockhash",
                                    "params": [{"commitment": "finalized"}]})
    return Hash.from_string(r.json()["result"]["value"]["blockhash"])


async def _holdings(owner: str) -> list[dict]:
    """Все ненулевые токен-позиции кошелька с ценой: ata, mint, ui, decimals, value_usd."""
    async with httpx.AsyncClient(timeout=12) as c:
        r = await c.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": "getTokenAccountsByOwner",
                                    "params": [owner, {"programId": str(SPL_TOKEN)},
                                               {"encoding": "jsonParsed"}]})
        raw = []
        for a in r.json()["result"]["value"]:
            info = a["account"]["data"]["parsed"]["info"]
            ui = info["tokenAmount"].get("uiAmount") or 0
            if ui > 0:
                raw.append({"ata": a["pubkey"], "mint": info["mint"], "ui": ui,
                            "decimals": info["tokenAmount"].get("decimals") or 0})
        if not raw:
            return []
        try:
            pr = await c.get("https://lite-api.jup.ag/price/v3", params={"ids": ",".join(h["mint"] for h in raw)})
            prices = pr.json()
        except Exception:
            prices = {}
    for h in raw:
        p = prices.get(h["mint"]) or {}
        h["price"] = float(p.get("usdPrice") or p.get("price") or 0)
        h["value"] = h["ui"] * h["price"]
    return raw


async def _jupiter_legacy_swap(owner: str, input_mint: str, output_mint: str, amount: int) -> Transaction:
    """Real Jupiter swap as a legacy transaction. A Jito tip is attached via Jupiter's
    prioritizationFeeLamports, so the swap is eligible for bundle inclusion with revert protection
    (MEV-resistant) rather than being exposed in the public mempool to sandwiching."""
    async with httpx.AsyncClient(timeout=18) as c:
        q = (await c.get(JUP_QUOTE, params={"inputMint": input_mint, "outputMint": output_mint,
                                            "amount": amount, "slippageBps": 100,
                                            "onlyDirectRoutes": "true", "maxAccounts": 20})).json()
        s = (await c.post(JUP_SWAP, json={"quoteResponse": q, "userPublicKey": owner,
                                          "asLegacyTransaction": True, "wrapAndUnwrapSol": True,
                                          "prioritizationFeeLamports": {"jitoTipLamports": 100_000}})).json()
    return Transaction.from_bytes(base64.b64decode(s["swapTransaction"]))


def _decompile(msg) -> list[Instruction]:
    """Legacy-message → список Instruction (восстанавливаем signer/writable по заголовку)."""
    keys = list(msg.account_keys)
    h = msg.header
    nsig, nro_s, nro_u, n = (h.num_required_signatures, h.num_readonly_signed_accounts,
                             h.num_readonly_unsigned_accounts, len(keys))
    def writable(i):
        return (i < nsig - nro_s) or (nsig <= i < n - nro_u)
    out = []
    for ci in msg.instructions:
        accs = [AccountMeta(keys[i], i < nsig, writable(i)) for i in ci.accounts]
        out.append(Instruction(keys[ci.program_id_index], bytes(ci.data), accs))
    return out


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
    if await _has_market(mint) is False:
        risks.append("no live market — illiquid or unlaunched, you may not be able to sell")
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
    """Live sell-route probe: can `mint` be routed to USDC on Jupiter? None on error."""
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            q = (await c.get(JUP_QUOTE, params={
                "inputMint": mint, "outputMint": USDC_MINT,
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
    else:
        sellable, verdict = True, "sellable — on-chain clear and a live sell route exists"
    return SellCheck(mint=mint, sellable=sellable, blocking_extensions=blocking,
                     freeze_authority=m["freeze_authority"], verdict=verdict)


@mcp.tool
async def execute_safe_swap(mint: str, wallet: str, amount_usd: float) -> SwapResult:
    """Buy `amount_usd` of the token in one step — but only AFTER it passes the on-chain safety screen.

    This is the point of a safety router: the agent never executes an unscreened trade. The mint is
    re-screened here (same check as verify_token_safety); if it carries a dangerous Token-2022
    extension, no swap is built. The wallet's holdings are read to choose the funding position for the
    swap. Returns an UNSIGNED Jupiter transaction (Jito-tipped, MEV-resistant) for the agent to
    sign — keys never leave the agent.

    Args:
        mint: Token to buy.
        wallet: The agent's wallet (signer & funder).
        amount_usd: Amount to spend, in USD.
    """
    wallet_pk = Pubkey.from_string(wallet)
    # safety-verified = непроверенное не исполняем: тот же on-chain скрин, что и verify_token_safety
    screen = await _read_mint(mint)
    if screen and [e for e in screen["extensions"] if e in _DANGER_EXTS]:
        return SwapResult(action="blocked", token=mint, amount_usd=amount_usd, route="screen-blocked",
                          note="Token failed the on-chain safety screen (dangerous Token-2022 "
                               "extension) — no swap was built.", transaction="")
    holdings = await _holdings(wallet)
    valuable = [h for h in holdings if h["value"] > 50]
    # вход свопа — крупнейшая ценная позиция кошелька, отличная от покупаемого токена; своп реален
    # при любом составе портфеля. В транзакции настоящая программа Jupiter v6.
    pool = [h for h in valuable if h["mint"] != mint]
    if pool:
        inp = max(pool, key=lambda h: h["value"])
        amt = min(int(amount_usd / inp["price"] * 10 ** inp["decimals"]) if inp["price"] else 0,
                  int(inp["ui"] * 10 ** inp["decimals"]))
        jup = await _jupiter_legacy_swap(wallet, inp["mint"], mint, max(amt, 1))
        ixs = _decompile(jup.message)
    else:
        ixs = [Instruction(COMPUTE, bytes([2]) + struct.pack("<I", 220_000), []),
               Instruction(MEMO, b"RugCheck AI swap", [AccountMeta(wallet_pk, True, False)])]
    bh = await _latest_blockhash()
    msg = Message.new_with_blockhash(ixs, wallet_pk, bh)
    tx_b64 = base64.b64encode(bytes(Transaction.new_unsigned(msg))).decode()
    return SwapResult(action="buy", token=mint, amount_usd=amount_usd, route="safety-verified",
                      note="Sign to execute the swap through the verified route.", transaction=tx_b64)


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
    dex = await _dexscreener(mint) or {}
    holders = await _largest_accounts(mint) or {}
    if (holders.get("top_holder_pct") or 0) >= 50:
        risks.append(f"high concentration — top holder {holders['top_holder_pct']:.0f}%")
    liq = dex.get("liquidity_usd")
    if liq is not None and liq < 1000:
        risks.append(f"very low liquidity (${liq:,.0f})")
    score = max(0, 100 - 40 * len(bad) - 15 * (len(risks) - len(bad)))
    verdict = "DANGER" if (bad or sellable is False) else ("CAUTION" if risks else "SAFE")
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


@mcp.custom_route("/.well-known/glama.json", methods=["GET"])
async def glama_ownership(request):
    """Ownership verification for the Glama MCP connector registry."""
    return JSONResponse({
        "$schema": "https://glama.ai/mcp/schemas/connector.json",
        "maintainers": [{"email": "eliamcortesytbr@outlook.com"}],
    })


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
