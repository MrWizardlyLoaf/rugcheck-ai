"""Tests for RugCheck AI screening configuration and tool registration."""
import server


def test_module_loads():
    assert server.mcp.name == "RugCheck AI"


def test_danger_extensions_defined():
    for e in ("permanentDelegate", "transferHook", "nonTransferable", "pausable"):
        assert e in server._DANGER_EXTS


def test_blocking_extensions_are_known_dangers():
    # каждое блокирующее продажу расширение должно быть в общем списке опасных
    assert server._BLOCKING_EXTS <= set(server._DANGER_EXTS)


def test_jupiter_endpoints_configured():
    assert "jup.ag" in server.JUP_QUOTE
    assert "jup.ag" in server.JUP_SWAP


def test_screening_helpers_present():
    # читатель чейна + рыночные пробы, на которых строится verdict
    for fn in ("_read_mint", "_has_market", "_can_route_sell"):
        assert callable(getattr(server, fn))
