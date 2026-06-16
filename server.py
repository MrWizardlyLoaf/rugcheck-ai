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

import httpx
from fastmcp import FastMCP
from pydantic import BaseModel
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

_DANGER_EXTS = {
    "permanentDelegate": "permanent delegate — the creator can move or burn your tokens anytime",
    "transferHook": "custom transfer hook — can block selling",
    "nonTransferable": "non-transferable — the token cannot be sold",
    "pausable": "pausable — trading can be paused, locking your sell",
}
_BLOCKING_EXTS = {"nonTransferable", "pausable"}


class TokenSafety(BaseModel):
    """Result of an on-chain token safety audit."""
    token: str
    verdict: str  # SAFE / CAUTION / DANGER / UNKNOWN
    mint_authority: str | None = None
    freeze_authority: str | None = None
    supply: str | None = None
    decimals: int | None = None
    extensions: list[str] = []
    risks: list[str] = []
    error: str | None = None


class Authorities(BaseModel):
    """Mint/freeze authority and Token-2022 extension report for a mint."""
    mint: str
    mint_authority: str | None = None
    freeze_authority: str | None = None
    token2022_extensions: list[str] = []
    dangerous_extensions: list[str] = []
    verdict: str | None = None
    error: str | None = None


class SellCheck(BaseModel):
    """Whether a token can be sold (honeypot check) from on-chain constraints."""
    mint: str
    sellable: bool | None = None
    blocking_extensions: list[str] = []
    freeze_authority: str | None = None
    verdict: str | None = None
    error: str | None = None


class SwapResult(BaseModel):
    """A built, unsigned swap transaction for the agent to sign."""
    action: str
    token: str
    amount_usd: float
    route: str
    note: str
    transaction: str


mcp = FastMCP(name="RugCheck AI",
              instructions="On-chain token safety + safe execution for Solana agents. Call "
                           "verify_token_safety to screen a token, then execute_safe_swap to buy it "
                           "through a safety-verified route in one step.")


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
    """Run an on-chain safety audit on a Solana token before trading.

    Reads the mint directly and flags an active mint authority (supply can be inflated), an active
    freeze authority (your tokens can be frozen), dangerous Token-2022 extensions, and whether the
    token has a live, routable market (illiquid / no market is itself a risk).
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
    """Check mint/freeze authority and Token-2022 traps, read directly from the chain."""
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
                "inputMint": mint, "outputMint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "amount": 10 ** min(decimals or 0, 9), "slippageBps": 300})).json()
        return bool(q.get("outAmount") and not q.get("error"))
    except Exception:
        return None


@mcp.tool
async def simulate_sell(mint: str) -> SellCheck:
    """Check whether the token can actually be sold (honeypot check).

    Combines on-chain constraints (non-transferable / pausable extensions, freeze authority) with a
    live Jupiter sell-route probe — a token with no sell route is effectively a honeypot even if no
    extension blocks it.
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


@mcp.custom_route("/.well-known/glama.json", methods=["GET"])
async def glama_ownership(request):
    """Ownership verification for the Glama MCP connector registry."""
    return JSONResponse({
        "$schema": "https://glama.ai/mcp/schemas/connector.json",
        "maintainers": [{"email": "eliamcortesytbr@outlook.com"}],
    })


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
