import pytest

from recon_agent.core.policy_engine import PolicyEngine, PolicyViolation
from recon_agent.core.state import AgentState, ToolCategory


def _make_state(in_scope: list[str], out_of_scope: list[str] | None = None) -> AgentState:
    return AgentState(
        program_url="https://hackerone.com/test",
        targets_in_scope=in_scope,
        targets_out_of_scope=out_of_scope or [],
    )


class TestPolicyEngineTarget:
    def test_allows_in_scope_target(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state)
        engine.check_target("example.com")  # should not raise

    def test_blocks_out_of_scope_target(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state)
        with pytest.raises(PolicyViolation):
            engine.check_target("evil.com")

    def test_allows_subdomain_with_wildcard(self):
        state = _make_state(["*.example.com"])
        engine = PolicyEngine(state)
        engine.check_target("sub.example.com")  # should not raise

    def test_blocks_explicitly_out_of_scope(self):
        state = _make_state(["*.example.com"], ["blog.example.com"])
        engine = PolicyEngine(state)
        with pytest.raises(PolicyViolation):
            engine.check_target("blog.example.com")

    def test_allows_url_target(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state)
        engine.check_target("https://example.com/api/v1")


class TestPolicyEngineCategory:
    def test_adaptive_allows_passive(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state, agent_mode="adaptive")
        engine.check_category(ToolCategory.RECON_PASSIVE)

    def test_adaptive_allows_web_scan(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state, agent_mode="adaptive")
        engine.check_category(ToolCategory.WEB_SCAN)

    def test_conservative_blocks_exploit(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state, agent_mode="conservative")
        with pytest.raises(PolicyViolation):
            engine.check_category(ToolCategory.EXPLOIT)

    def test_conservative_blocks_active_recon(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state, agent_mode="conservative")
        with pytest.raises(PolicyViolation):
            engine.check_category(ToolCategory.RECON_ACTIVE)

    def test_custom_blocked_categories(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(
            state, blocked_categories=[ToolCategory.WEB_SCAN]
        )
        with pytest.raises(PolicyViolation):
            engine.check_category(ToolCategory.WEB_SCAN)


class TestRequiresApproval:
    def test_adaptive_requires_approval_for_exploit(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state, agent_mode="adaptive")
        assert engine.requires_approval(ToolCategory.EXPLOIT) is True

    def test_adaptive_requires_approval_for_active_recon(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state, agent_mode="adaptive")
        assert engine.requires_approval(ToolCategory.RECON_ACTIVE) is True

    def test_adaptive_no_approval_for_passive(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state, agent_mode="adaptive")
        assert engine.requires_approval(ToolCategory.RECON_PASSIVE) is False

    def test_conservative_never_requires_approval(self):
        state = _make_state(["example.com"])
        engine = PolicyEngine(state, agent_mode="conservative")
        assert engine.requires_approval(ToolCategory.EXPLOIT) is False
