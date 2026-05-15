import pytest

from recon_agent.tools.recon.subfinder import SubfinderTool
from recon_agent.tools.recon.httpx_tool import HttpxTool
from recon_agent.tools.web.nuclei import NucleiTool
from recon_agent.core.state import ToolCategory


class TestSubfinderTool:
    def test_validate_valid_domain(self):
        tool = SubfinderTool()
        assert tool.validate_args("example.com") is True

    def test_validate_wildcard_domain(self):
        tool = SubfinderTool()
        assert tool.validate_args("*.example.com") is True

    def test_validate_subdomain(self):
        tool = SubfinderTool()
        assert tool.validate_args("api.example.com") is True

    def test_validate_rejects_empty(self):
        tool = SubfinderTool()
        assert tool.validate_args("") is False

    def test_validate_rejects_ip(self):
        tool = SubfinderTool()
        assert tool.validate_args("192.168.1.1") is False

    def test_category(self):
        assert SubfinderTool.category == ToolCategory.RECON_PASSIVE

    def test_no_approval_required(self):
        assert SubfinderTool.requires_approval is False


class TestHttpxTool:
    def test_validate_valid_target(self):
        tool = HttpxTool()
        assert tool.validate_args("example.com") is True

    def test_validate_valid_url(self):
        tool = HttpxTool()
        assert tool.validate_args("https://example.com") is True

    def test_validate_rejects_empty(self):
        tool = HttpxTool()
        assert tool.validate_args("") is False

    def test_category(self):
        assert HttpxTool.category == ToolCategory.RECON_ACTIVE


class TestNucleiTool:
    def test_validate_valid_severity(self):
        tool = NucleiTool()
        assert tool.validate_args("example.com", severity="critical,high") is True

    def test_validate_single_severity(self):
        tool = NucleiTool()
        assert tool.validate_args("example.com", severity="medium") is True

    def test_validate_rejects_invalid_severity(self):
        tool = NucleiTool()
        assert tool.validate_args("example.com", severity="critical,rce") is False

    def test_validate_rejects_empty_target(self):
        tool = NucleiTool()
        assert tool.validate_args("", severity="high") is False

    def test_category(self):
        assert NucleiTool.category == ToolCategory.WEB_SCAN

    def test_no_approval_required(self):
        assert NucleiTool.requires_approval is False


class TestToolRegistry:
    def test_build_default_registry(self):
        from recon_agent.tools.registry import build_default_registry
        registry = build_default_registry()
        assert "subfinder" in registry
        assert "httpx" in registry
        assert "nuclei" in registry

    def test_get_unknown_tool_raises(self):
        from recon_agent.tools.registry import ToolRegistry
        registry = ToolRegistry()
        with pytest.raises(KeyError):
            registry.get("nonexistent")

    def test_register_and_retrieve(self):
        from recon_agent.tools.registry import ToolRegistry
        registry = ToolRegistry()
        tool = SubfinderTool()
        registry.register(tool)
        assert registry.get("subfinder") is tool
