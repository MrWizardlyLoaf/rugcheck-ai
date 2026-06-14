"""RugCheck AI — On-chain token safety + safe execution for Solana AI agents.

Reads the token mint directly from Solana (getAccountInfo) to check mint/freeze authority, supply,
and Token-2022 extension traps, then builds the swap through Jupiter with MEV protection (Jito tip
+ revert protection) and a dynamic compute-unit budget. Open source — the screening tools are
read-only; the swap tool only builds an unsigned transaction for you to sign.
"""
import os
from typing import Annotated, Literal

import httpx
from fastmcp import FastMCP
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse

RPC = os.environ.get("SOLANA_RPC", "https://api.mainnet-beta.solana.com")
JUP_QUOTE = "https://lite-api.jup.ag/swap/v1/quote"
JUP_SWAP = "https://lite-api.jup.ag/swap/v1/swap"
JITO_TIP_LAMPORTS = 1000  # Jito tip → revert protection + front-run resistance

_DANGER_EXTS = {
    "permanentDelegate": "permanent delegate — the creator can move or burn your tokens anytime",
    "transferHook": "custom transfer hook — can block selling",
    "nonTransferable": "non-transferable — the token cannot be sold",
    "pausable": "pausable — trading can be paused, locking your sell",
    "defaultAccountState": "default-frozen — new token accounts start frozen, you may be unable to sell",
}
# Extensions that can outright block a sale (honeypot mechanics).
_BLOCKING_EXTS = {"nonTransferable", "pausable", "transferHook", "defaultAccountState"}

Verdict = Literal["SAFE", "CAUTION", "DANGER", "UNKNOWN"]


class TokenSafety(BaseModel):
    """Result of an on-chain token safety audit."""
    token: str
    verdict: Verdict
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
    verdict: Verdict = "UNKNOWN"
    summary: str | None = None
    mint_authority: str | None = None
    freeze_authority: str | None = None
    token2022_extensions: list[str] = []
    dangerous_extensions: list[str] = []
    error: str | None = None


class SellCheck(BaseModel):
    """Whether a token can be sold (honeypot check) from on-chain constraints."""
    mint: str
    verdict: Verdict = "UNKNOWN"
    summary: str | None = None
    sellable: bool | None = None
    blocking_extensions: list[str] = []
    freeze_authority: str | None = None
    error: str | None = None


class SwapResult(BaseModel):
    """A built, unsigned swap transaction for the agent to sign."""
    action: str
    input_mint: str
    output_mint: str
    amount: float
    route: str
    note: str
    transaction: str = ""
    error: str | None = None


mcp = FastMCP(name="RugCheck AI",
              instructions="On-chain Solana token safety + swap execution. Call verify_token_safety "
                           "(read-only) to screen a token, then execute_safe_swap to build a "
                           "Jupiter swap (MEV-protected via a Jito tip) returned unsigned for you "
                           "to sign. The swap tool screens the output token before building.")


async def _read_mint(mint: str) -> dict | None:
    """Read the mint account directly from Solana: authorities, supply, decimals, extensions, owner."""
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
            "decimals": info.get("decimals"), "supply": info.get("supply"), "extensions": exts,
            "owner": value.get("owner")}


async def _jupiter_swap(owner: str, input_mint: str, output_mint: str, amount: int) -> dict:
    """Build a MEV-protected swap via Jupiter: Jito tip (revert protection) + dynamic compute budget.

    Returns {'swapTransaction': base64} on success, or {'error': msg} on any failure (no route,
    Jupiter down, malformed response) — never raises.
    """
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            q = (await c.get(JUP_QUOTE, params={"inputMint": input_mint, "outputMint": output_mint,
                                                "amount": amount, "slippageBps": 100})).json()
            if not isinstance(q, dict) or "outAmount" not in q:
                msg = q.get("error") if isinstance(q, dict) else "bad quote response"
                return {"error": msg or "no swap route for this pair"}
            s = (await c.post(JUP_SWAP, json={
                "quoteResponse": q, "userPublicKey": owner, "wrapAndUnwrapSol": True,
                "asLegacyTransaction": True, "dynamicComputeUnitLimit": True,
                "prioritizationFeeLamports": {"jitoTipLamports": JITO_TIP_LAMPORTS}})).json()
    except Exception as e:
        return {"error": f"Jupiter unavailable ({type(e).__name__})"}
    if not isinstance(s, dict) or "swapTransaction" not in s:
        msg = s.get("error") if isinstance(s, dict) else "bad swap response"
        return {"error": msg or "swap build failed"}
    return {"swapTransaction": s["swapTransaction"]}


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
async def verify_token_safety(
    mint: Annotated[str, Field(description="The SPL / Token-2022 mint address to screen.")],
) -> TokenSafety:
    """Run an on-chain safety audit on a Solana token before trading (read-only).

    Reads the mint directly and flags an active mint authority (supply can be inflated), an active
    freeze authority (your tokens can be frozen), and dangerous Token-2022 extensions. An active
    mint or freeze authority is treated as DANGER — it is the canonical rug vector.
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
    verdict: Verdict = ("DANGER" if (bad_exts or m["mint_authority"] or m["freeze_authority"])
                        else "CAUTION" if risks else "SAFE")
    return TokenSafety(token=mint, verdict=verdict, mint_authority=m["mint_authority"],
                       freeze_authority=m["freeze_authority"], supply=m["supply"], decimals=m["decimals"],
                       extensions=m["extensions"], risks=risks or ["no authority or extension red flags"])


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
async def check_authorities(
    mint: Annotated[str, Field(description="The SPL / Token-2022 mint address to inspect.")],
) -> Authorities:
    """Check mint/freeze authority and Token-2022 traps, read directly from the chain (read-only)."""
    m = await _read_mint(mint)
    if not m:
        return Authorities(mint=mint, verdict="UNKNOWN", error="not an SPL/Token-2022 mint, or RPC unavailable")
    traps = [e for e in m["extensions"] if e in _DANGER_EXTS]
    danger = bool(traps or m["mint_authority"] or m["freeze_authority"])
    return Authorities(mint=mint, verdict="DANGER" if danger else "SAFE",
                       summary="authorities or dangerous extensions present — review" if danger
                       else "no mint/freeze authority and no dangerous extensions",
                       mint_authority=m["mint_authority"], freeze_authority=m["freeze_authority"],
                       token2022_extensions=m["extensions"], dangerous_extensions=traps)


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
async def simulate_sell(
    mint: Annotated[str, Field(description="The SPL / Token-2022 mint address to test for sellability.")],
) -> SellCheck:
    """Check whether the token can actually be sold (honeypot check) from on-chain constraints (read-only).

    Treats an active freeze authority and any sell-blocking Token-2022 extension (transfer hook,
    non-transferable, pausable, default-frozen) as a reason it may NOT be sellable.
    """
    m = await _read_mint(mint)
    if not m:
        return SellCheck(mint=mint, verdict="UNKNOWN", error="not an SPL/Token-2022 mint, or RPC unavailable")
    blocking = [e for e in m["extensions"] if e in _BLOCKING_EXTS]
    sellable = not blocking and not m["freeze_authority"]
    reasons = list(blocking) + (["freeze authority active"] if m["freeze_authority"] else [])
    return SellCheck(mint=mint, verdict="SAFE" if sellable else "DANGER", sellable=sellable,
                     blocking_extensions=blocking, freeze_authority=m["freeze_authority"],
                     summary="sellable — no on-chain block found" if sellable
                     else f"NOT sellable — {', '.join(reasons)}")


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True})
async def execute_safe_swap(
    input_mint: Annotated[str, Field(description="The token you pay with (mint address).")],
    output_mint: Annotated[str, Field(description="The token you want to receive (mint address).")],
    wallet: Annotated[str, Field(description="Your wallet address (signer & funder).")],
    amount: Annotated[float, Field(description="Amount of input_mint to swap, in human units (e.g. 50 = 50 USDC).")],
) -> SwapResult:
    """Build a Jupiter swap of `amount` of `input_mint` into `output_mint`, MEV-protected via a Jito
    tip (revert protection) with a dynamic compute-unit budget.

    The output token is screened on-chain first, then Jupiter's transaction is returned UNCHANGED for
    you to sign. Nothing is broadcast until you sign. `route` reflects whether the output token passed
    screening.
    """
    inp = await _read_mint(input_mint)
    decimals = inp["decimals"] if inp and inp.get("decimals") is not None else 6
    base_amount = max(int(amount * 10 ** decimals), 1)
    res = await _jupiter_swap(wallet, input_mint, output_mint, base_amount)
    if "error" in res:
        return SwapResult(action="swap", input_mint=input_mint, output_mint=output_mint, amount=amount,
                          route="none", note="Could not build the swap.", error=res["error"])
    out = await _read_mint(output_mint)
    clean = bool(out and not out["mint_authority"] and not out["freeze_authority"]
                 and not [e for e in out["extensions"] if e in _DANGER_EXTS])
    route = "screened-clean" if clean else "unscreened — output token has authority/extension flags, review"
    return SwapResult(action="swap", input_mint=input_mint, output_mint=output_mint, amount=amount,
                      route=route, note="Sign to execute the Jupiter swap.", transaction=res["swapTransaction"])


@mcp.custom_route("/.well-known/glama.json", methods=["GET"])
async def glama_ownership(request):
    """Ownership verification for the Glama MCP connector registry."""
    return JSONResponse({
        "$schema": "https://glama.ai/mcp/schemas/connector.json",
        "maintainers": [{"email": "mrwizardlyloaf@users.noreply.github.com"}],
    })


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
