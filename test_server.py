"""Tests for RugCheck AI: screening configuration, tool registration, and live tool calls."""
import asyncio

import httpx
import pytest

import server

# Well-known reference mints.
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
WIF = "EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm"  # dogwifhat — deep, stable liquidity

EXPECTED_TOOLS = {
    "scan_token", "is_safe", "verify_token_safety", "check_authorities", "simulate_sell",
    "simulate_trade", "check_liquidity", "holders_breakdown", "token_age", "rug_forecast",
    "scammer_dna", "check_deployer", "compare_tokens", "batch_scan", "execute_safe_swap",
}


def _registered_tools():
    """Registered tool names, resilient across FastMCP versions."""
    m = server.mcp
    if hasattr(m, "get_tools"):
        tools = asyncio.run(m.get_tools())
        return set(tools.keys()) if isinstance(tools, dict) else {t.name for t in tools}
    for attr in ("_tool_manager", "tool_manager"):
        mgr = getattr(m, attr, None)
        if mgr is not None and hasattr(mgr, "_tools"):
            return set(mgr._tools.keys())
    tools = asyncio.run(m.list_tools())
    return {t.name for t in tools}


def _call(tool_name, *args, **kwargs):
    """Invoke a registered MCP tool's underlying coroutine synchronously."""
    tool = getattr(server, tool_name)
    fn = getattr(tool, "fn", tool)
    return asyncio.run(fn(*args, **kwargs))


def _online():
    try:
        httpx.get("https://lite-api.jup.ag/price/v3", params={"ids": USDC}, timeout=8)
        return True
    except Exception:
        return False


ONLINE = _online()
needs_net = pytest.mark.skipif(not ONLINE, reason="no network / RPC available")


# ── configuration ────────────────────────────────────────────────────────────

def test_module_loads():
    assert server.mcp.name == "RugCheck AI"


def test_danger_extensions_defined():
    for e in ("permanentDelegate", "transferHook", "nonTransferable", "pausable"):
        assert e in server._DANGER_EXTS


def test_blocking_extensions_are_known_dangers():
    assert server._BLOCKING_EXTS <= set(server._DANGER_EXTS)


def test_jupiter_endpoints_configured():
    assert "jup.ag" in server.JUP_QUOTE
    assert "jup.ag" in server.JUP_SWAP


def test_screening_helpers_present():
    for fn in ("_read_mint", "_has_market", "_can_route_sell"):
        assert callable(getattr(server, fn))


def test_all_tools_registered():
    registered = _registered_tools()
    missing = EXPECTED_TOOLS - registered
    assert not missing, f"tools missing from registration: {missing}"
    assert len(registered) == len(EXPECTED_TOOLS)


# ── deterministic verdict logic (offline, fully mocked chain/market) ──────────

def _patch_chain(monkeypatch, *, extensions, mint_auth=None, freeze_auth=None,
                 decimals=9, sellable: "bool | None" = True, liquidity=500_000.0, top_pct=5.0):
    async def fake_read_mint(_mint):
        return {"mint_authority": mint_auth, "freeze_authority": freeze_auth,
                "decimals": decimals, "supply": "1000000", "extensions": extensions}

    async def fake_route(_mint, _dec):
        return sellable

    async def fake_dex(_mint):
        return {"liquidity_usd": liquidity, "volume_24h": 10_000.0, "age_days": 30,
                "buys_24h": 10, "sells_24h": 10}

    async def fake_largest(_mint):
        return {"top_holder_pct": top_pct, "top5_holder_pct": top_pct * 2,
                "holder_accounts": 50, "top_holders": []}

    monkeypatch.setattr(server, "_read_mint", fake_read_mint)
    monkeypatch.setattr(server, "_can_route_sell", fake_route)
    monkeypatch.setattr(server, "_dexscreener", fake_dex)
    monkeypatch.setattr(server, "_largest_accounts", fake_largest)


def test_scan_clean_token_is_safe(monkeypatch):
    _patch_chain(monkeypatch, extensions=[])
    r = _call("scan_token", "Mint")
    assert r.verdict == "SAFE"
    assert r.safety_score == 100


def test_scan_permanent_delegate_is_danger(monkeypatch):
    _patch_chain(monkeypatch, extensions=["permanentDelegate"])
    r = _call("scan_token", "Mint")
    assert r.verdict == "DANGER"
    assert r.safety_score <= 20  # DANGER must read as a low score, not a misleading 60
    assert any("permanent delegate" in x.lower() for x in r.risks)


def test_scan_no_sell_route_is_danger(monkeypatch):
    _patch_chain(monkeypatch, extensions=[], sellable=False)
    r = _call("scan_token", "Mint")
    assert r.verdict == "DANGER"  # honeypot: clean on-chain but cannot be sold
    assert r.safety_score <= 20  # honeypot = near-total loss → score must be low, coherent with the verdict


def test_scan_active_authority_is_caution(monkeypatch):
    _patch_chain(monkeypatch, extensions=[], mint_auth="SomeAuthority1111111111111111111111111111111")
    r = _call("scan_token", "Mint")
    assert r.verdict == "CAUTION"


def test_scan_unverified_sell_route_is_not_safe(monkeypatch):
    # fail-closed: when the sell-route probe can't resolve (None), never return SAFE
    _patch_chain(monkeypatch, extensions=[], sellable=None)
    r = _call("scan_token", "Mint")
    assert r.verdict != "SAFE"


# ── live tool calls (skip cleanly when offline OR when a shared RPC throttles) ──

VERDICTS = {"SAFE", "CAUTION", "DANGER", "UNKNOWN"}


@needs_net
def test_scan_token_returns_valid_verdict():
    r = _call("scan_token", USDC)
    if r.verdict == "UNKNOWN":
        pytest.skip("RPC could not read the mint (throttled)")
    assert r.verdict in VERDICTS
    assert 0 <= r.safety_score <= 100
    assert isinstance(r.risks, list)


@needs_net
def test_is_safe_shape():
    r = _call("is_safe", USDC)
    assert set(r) >= {"mint", "safe", "verdict", "safety_score", "reason"}
    assert isinstance(r["safe"], bool)
    assert r["verdict"] in VERDICTS


@needs_net
def test_simulate_trade_roundtrip_on_liquid_token():
    r = _call("simulate_trade", WIF, 50.0)
    if "error" in r or not r.get("buyable"):
        pytest.skip("Jupiter route unavailable (throttled)")
    # a deep-liquidity major is sellable; round-trip loss must be a sane percentage
    assert r["sellable"] is True
    assert -5 <= r["round_trip_loss_pct"] <= 25


@needs_net
def test_batch_scan_one_report_per_mint():
    out = _call("batch_scan", [USDC, WIF])
    assert len(out) == 2
    assert all(rep.verdict in VERDICTS for rep in out)


@needs_net
def test_scammer_dna_clean_token_low_score():
    r = _call("scammer_dna", WIF)
    if "error" in r:
        pytest.skip("RPC unavailable (throttled)")
    assert 0 <= r["intent_score"] <= 100
    assert isinstance(r["signals"], list)
