"""SolGuard — on-chain token safety for Solana agents."""
import os

from fastmcp import FastMCP

mcp = FastMCP(name="SolGuard")


@mcp.tool
async def verify_token_safety(mint: str) -> dict:
    """Screen a Solana token for safety before trading (WIP)."""
    return {"token": mint, "verdict": "unknown", "note": "WIP"}


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
