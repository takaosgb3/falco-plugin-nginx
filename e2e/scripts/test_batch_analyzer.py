#!/usr/bin/env python3
"""
Unit tests for batch_analyzer.py

Issue #53: E2E ルールマッピング検証機能

Test coverage for:
- normalize_rule_name(): Rule name normalization
- compare_rules(): Rule matching logic
"""

import pytest
from batch_analyzer import normalize_rule_name, compare_rules


class TestNormalizeRuleName:
    """Tests for normalize_rule_name() function"""

    def test_none_input(self):
        """Should return empty string for None input"""
        assert normalize_rule_name(None) == ""

    def test_empty_string(self):
        """Should return empty string for empty string input"""
        assert normalize_rule_name("") == ""

    def test_simple_name_lowercase(self):
        """Should lowercase simple rule name"""
        assert normalize_rule_name("Simple Rule Name") == "simple rule name"

    def test_name_with_nginx_prefix(self):
        """Should remove [NGINX XXX] prefix and lowercase"""
        assert normalize_rule_name("[NGINX SQLi] Advanced SQL Injection Attempt") == "advanced sql injection attempt"

    def test_name_with_nginx_xss_prefix(self):
        """Should remove [NGINX XSS] prefix and lowercase"""
        assert normalize_rule_name("[NGINX XSS] Cross-Site Scripting") == "cross-site scripting"

    def test_name_with_nginx_traversal_prefix(self):
        """Should remove [NGINX Traversal] prefix and lowercase"""
        assert normalize_rule_name("[NGINX Traversal] File inclusion attack detected") == "file inclusion attack detected"

    def test_name_with_whitespace(self):
        """Should strip leading/trailing whitespace"""
        assert normalize_rule_name("  Rule with spaces  ") == "rule with spaces"

    def test_name_with_prefix_and_whitespace(self):
        """Should handle prefix and whitespace correctly"""
        assert normalize_rule_name("[NGINX Test]   Spaced Rule  ") == "spaced rule"

    def test_name_without_matching_prefix(self):
        """Should lowercase name without [NGINX] prefix"""
        assert normalize_rule_name("[OTHER] Some Rule") == "[other] some rule"

    def test_partial_nginx_prefix(self):
        """Should not match partial NGINX prefix"""
        assert normalize_rule_name("[NGINX Some Rule") == "[nginx some rule"

    # === Type Validation Tests ===
    def test_integer_input(self):
        """Should return empty string for integer input (type validation)"""
        assert normalize_rule_name(123) == ""

    def test_list_input(self):
        """Should return empty string for list input (type validation)"""
        assert normalize_rule_name(['test']) == ""

    def test_dict_input(self):
        """Should return empty string for dict input (type validation)"""
        assert normalize_rule_name({'name': 'test'}) == ""


class TestCompareRules:
    """Tests for compare_rules() function"""

    # === Null/Empty Input Tests ===
    def test_both_empty(self):
        """Should return False when both inputs are empty"""
        assert compare_rules("", "") is False

    def test_expected_empty(self):
        """Should return False when expected_rule is empty"""
        assert compare_rules("", "Some Rule") is False

    def test_actual_empty(self):
        """Should return False when rule_name is empty"""
        assert compare_rules("Some Rule", "") is False

    def test_both_none(self):
        """Should return False when both inputs are None (via empty string handling)"""
        # Note: Function expects strings, None should be handled externally
        # This tests the empty string path
        assert compare_rules("", "") is False

    def test_expected_none(self):
        """Should return False when expected_rule is None"""
        # normalize_rule_name handles None -> "", compare_rules returns False for empty
        assert compare_rules(None, "Some Rule") is False

    def test_actual_none(self):
        """Should return False when rule_name is None"""
        # normalize_rule_name handles None -> "", compare_rules returns False for empty
        assert compare_rules("Some Rule", None) is False

    def test_both_none_direct(self):
        """Should return False when both inputs are None directly"""
        assert compare_rules(None, None) is False

    # === Exact Match Tests ===
    def test_exact_match(self):
        """Should return True for exact match"""
        assert compare_rules("SQL Injection Attempt", "SQL Injection Attempt") is True

    def test_exact_match_with_prefix(self):
        """Should return True when both have same prefix"""
        assert compare_rules(
            "[NGINX SQLi] Advanced SQL Injection",
            "[NGINX SQLi] Advanced SQL Injection"
        ) is True

    # === Normalized Match Tests ===
    def test_normalized_match_case_insensitive(self):
        """Should match case-insensitively after normalization"""
        assert compare_rules(
            "Advanced SQL Injection Attempt",
            "ADVANCED SQL INJECTION ATTEMPT"
        ) is True

    def test_normalized_match_with_prefix_in_expected(self):
        """Should match when expected has prefix but actual doesn't"""
        assert compare_rules(
            "[NGINX SQLi] Advanced SQL Injection Attempt",
            "Advanced SQL Injection Attempt"
        ) is True

    def test_normalized_match_with_prefix_in_actual(self):
        """Should match when actual has prefix but expected doesn't"""
        assert compare_rules(
            "Advanced SQL Injection Attempt",
            "[NGINX SQLi] Advanced SQL Injection Attempt"
        ) is True

    def test_normalized_match_different_prefixes(self):
        """Should match when both have different prefixes but same core name"""
        assert compare_rules(
            "[NGINX SQLi] SQL Injection Attack",
            "[NGINX Advanced] SQL Injection Attack"
        ) is True

    # === Substring Match Tests ===
    def test_substring_match_long_expected(self):
        """Should match when normalized expected (>=10 chars) is substring of actual"""
        assert compare_rules(
            "sql injection",  # 13 chars
            "[NGINX SQLi] Advanced SQL Injection Attack Detected"
        ) is True

    def test_substring_match_short_expected(self):
        """Should NOT match substring when expected < 10 chars"""
        assert compare_rules(
            "sql test",  # 8 chars
            "sql test injection"
        ) is False

    def test_substring_match_exactly_10_chars(self):
        """Should match substring when expected is exactly 10 chars"""
        assert compare_rules(
            "0123456789",  # exactly 10 chars
            "prefix 0123456789 suffix"
        ) is True

    def test_substring_match_9_chars(self):
        """Should NOT match substring when expected is 9 chars"""
        assert compare_rules(
            "123456789",  # 9 chars
            "prefix 123456789 suffix"
        ) is False

    # === Mismatch Tests ===
    def test_complete_mismatch(self):
        """Should return False for completely different rules"""
        assert compare_rules("SQL Injection", "XSS Attack") is False

    def test_partial_overlap_not_substring(self):
        """Should return False when partial overlap but not substring"""
        assert compare_rules(
            "sql injection attempt",
            "sql attack detected"
        ) is False

    # === Edge Cases ===
    def test_whitespace_handling(self):
        """Should handle whitespace in rule names"""
        assert compare_rules(
            "  Rule With Spaces  ",
            "Rule With Spaces"
        ) is True

    def test_special_characters(self):
        """Should handle special characters in rule names"""
        assert compare_rules(
            "[NGINX XSS] Cross-Site Scripting (Reflected)",
            "Cross-Site Scripting (Reflected)"
        ) is True


class TestCompareRulesIntegration:
    """Integration tests using realistic rule names from the project"""

    def test_sqli_rule_match(self):
        """Test SQL Injection rule matching"""
        expected = "[NGINX SQLi] Advanced SQL Injection Attempt"
        actual = "[NGINX SQLi] Advanced SQL Injection Attempt"
        assert compare_rules(expected, actual) is True

    def test_xss_rule_match(self):
        """Test XSS rule matching"""
        expected = "[NGINX XSS] Cross-Site Scripting (Reflected)"
        actual = "Cross-Site Scripting (Reflected)"
        assert compare_rules(expected, actual) is True

    def test_traversal_rule_match(self):
        """Test Path Traversal rule matching"""
        expected = "[NGINX Traversal] File inclusion attack detected"
        actual = "[NGINX Traversal] File inclusion attack detected"
        assert compare_rules(expected, actual) is True

    def test_xxe_rule_match(self):
        """Test XXE rule matching"""
        expected = "[NGINX XXE Attack] DOCTYPE/ENTITY injection"
        actual = "DOCTYPE/ENTITY injection"
        assert compare_rules(expected, actual) is True

    def test_cmd_injection_rule_match(self):
        """Test Command Injection rule matching"""
        expected = "[NGINX CmdInj] Command injection attempt"
        actual = "[NGINX CmdInj] Command injection attempt"
        assert compare_rules(expected, actual) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
