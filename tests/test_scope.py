import pytest

from recon_agent.core.scope import is_in_scope, parse_scope_list, normalize_scope_entry


class TestIsInScope:
    def test_exact_match(self):
        assert is_in_scope("example.com", ["example.com"], [])

    def test_exact_match_url(self):
        assert is_in_scope("https://example.com/path", ["example.com"], [])

    def test_wildcard_match_subdomain(self):
        assert is_in_scope("sub.example.com", ["*.example.com"], [])

    def test_wildcard_match_root(self):
        # *.example.com should also match example.com itself
        assert is_in_scope("example.com", ["*.example.com"], [])

    def test_wildcard_does_not_match_other_domain(self):
        assert not is_in_scope("other.com", ["*.example.com"], [])

    def test_out_of_scope_overrides_in_scope(self):
        assert not is_in_scope(
            "blog.example.com",
            ["*.example.com"],
            ["blog.example.com"],
        )

    def test_not_in_scope(self):
        assert not is_in_scope("evil.com", ["example.com"], [])

    def test_url_with_port(self):
        assert is_in_scope("https://example.com:8080/api", ["example.com"], [])

    def test_multiple_in_scope(self):
        assert is_in_scope("api.example.com", ["example.com", "api.example.com"], [])

    def test_empty_in_scope(self):
        assert not is_in_scope("example.com", [], [])


class TestParseScopeList:
    def test_comma_separated(self):
        result = parse_scope_list("example.com, api.example.com")
        assert result == ["example.com", "api.example.com"]

    def test_newline_separated(self):
        result = parse_scope_list("example.com\napi.example.com")
        assert result == ["example.com", "api.example.com"]

    def test_strips_whitespace(self):
        result = parse_scope_list("  example.com  ,  api.example.com  ")
        assert result == ["example.com", "api.example.com"]

    def test_empty_entries_ignored(self):
        result = parse_scope_list("example.com,,api.example.com")
        assert result == ["example.com", "api.example.com"]

    def test_url_input_normalized(self):
        result = parse_scope_list("https://example.com")
        assert result == ["example.com"]

    def test_wildcard_preserved(self):
        result = parse_scope_list("*.example.com")
        assert result == ["*.example.com"]

    def test_empty_string(self):
        result = parse_scope_list("")
        assert result == []
