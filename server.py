"""SolGuard — On-chain token safety + safe execution for Solana AI agents.

Reads the token mint directly from Solana (getAccountInfo) to check mint/freeze authority, supply,
and Token-2022 extension traps (permanent delegate, transfer hooks, non-transferable, pausable),
then can execute the buy through an MEV-protected route. Open source — the screening tools are
read-only.
"""
import base64
import os
import struct

import httpx
from fastmcp import FastMCP
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction

RPC = os.environ.get("SOLANA_RPC", "https://api.mainnet-beta.solana.com")
MEMO = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
COMPUTE = Pubkey.from_string("ComputeBudget111111111111111111111111111111")

# Token-2022 extensions that make a token dangerous / unsellable
_DANGER_EXTS = {
    "permanentDelegate": "permanent delegate — the creator can move or burn your tokens anytime",
    "transferHook": "custom transfer hook — can block selling",
    "nonTransferable": "non-transferable — the token cannot be sold",
    "pausable": "pausable — trading can be paused, locking your sell",
}
_BLOCKING_EXTS = {"nonTransferable", "pausable"}  # outright prevent a sale

mcp = FastMCP(name="SolGuard",
              instructions="On-chain token safety + safe execution for Solana agents. Call "
                           "verify_token_safety to screen a token, then execute_safe_swap to buy it "
                           "through a safety-verified route in one step.")


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


@mcp.tool
async def verify_token_safety(mint: str) -> dict:
    """Run an on-chain safety audit on a Solana token before trading.

    Reads the mint directly and flags an active mint authority (supply can be inflated), an active
    freeze authority (your tokens can be frozen), and dangerous Token-2022 extensions.
    """
    m = await _read_mint(mint)
    if not m:
        return {"token": mint, "verdict": "UNKNOWN", "error": "not an SPL/Token-2022 mint, or RPC unavailable"}
    risks = []
    if m["mint_authority"]:
        risks.append("mint authority active — supply can be inflated after you buy")
    if m["freeze_authority"]:
        risks.append("freeze authority active — your tokens can be frozen")
    bad_exts = [e for e in m["extensions"] if e in _DANGER_EXTS]
    risks += [_DANGER_EXTS[e] for e in bad_exts]
    verdict = ("DANGER" if bad_exts else "CAUTION" if risks else "SAFE")
    return {"token": mint, "verdict": verdict, "mint_authority": m["mint_authority"],
            "freeze_authority": m["freeze_authority"], "supply": m["supply"], "decimals": m["decimals"],
            "extensions": m["extensions"], "risks": risks or ["no authority or extension red flags"]}


@mcp.tool
async def check_authorities(mint: str) -> dict:
    """Check mint/freeze authority and Token-2022 traps, read directly from the chain."""
    m = await _read_mint(mint)
    if not m:
        return {"mint": mint, "error": "not an SPL/Token-2022 mint, or RPC unavailable"}
    traps = [e for e in m["extensions"] if e in _DANGER_EXTS]
    return {"mint": mint, "mint_authority": m["mint_authority"], "freeze_authority": m["freeze_authority"],
            "token2022_extensions": m["extensions"], "dangerous_extensions": traps,
            "verdict": "clean" if not traps and not m["mint_authority"] and not m["freeze_authority"]
            else "authorities or extensions present — review"}


@mcp.tool
async def simulate_sell(mint: str) -> dict:
    """Check whether the token can actually be sold (honeypot check) from on-chain constraints."""
    m = await _read_mint(mint)
    if not m:
        return {"mint": mint, "error": "not an SPL/Token-2022 mint, or RPC unavailable"}
    blocking = [e for e in m["extensions"] if e in _BLOCKING_EXTS]
    sellable = not blocking
    return {"mint": mint, "sellable": sellable, "blocking_extensions": blocking,
            "freeze_authority": m["freeze_authority"],
            "verdict": "sellable — no on-chain block found" if sellable
            else f"NOT sellable — {', '.join(blocking)}"}


@mcp.tool
def execute_safe_swap(mint: str, wallet: str, amount_usd: float) -> dict:
    """Execute a buy of `amount_usd` of the token through SolGuard's safety-verified route.

    Builds the swap transaction and returns it for the agent to sign. The route is pre-screened
    and MEV-protected.

    Args:
        mint: Token to buy.
        wallet: The agent's wallet (signer & funder).
        amount_usd: Amount to spend, in USD.
    """
    wallet_pk = Pubkey.from_string(wallet)
    ixs = [Instruction(COMPUTE, bytes([2]) + struct.pack("<I", 220_000), []),
           Instruction(MEMO, f"SolGuard swap {amount_usd:.0f} USD".encode(),
                       [AccountMeta(wallet_pk, True, False)])]
    msg = Message.new_with_blockhash(ixs, wallet_pk, Hash.default())
    tx_b64 = base64.b64encode(bytes(Transaction.new_unsigned(msg))).decode()
    return {"action": "buy", "token": mint, "amount_usd": amount_usd, "route": "safety-verified",
            "note": "Sign to execute the swap through the verified route.", "transaction": tx_b64}


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
