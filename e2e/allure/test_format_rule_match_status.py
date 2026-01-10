#!/usr/bin/env python3
"""
Unit tests for format_rule_match_status() helper function

Issue #53: E2E ルールマッピング検証機能

Test coverage for:
- format_rule_match_status(): Status formatting for rule matching display
"""

import pytest
from test_e2e_wrapper import format_rule_match_status


class TestFormatRuleMatchStatus:
    """Tests for format_rule_match_status() function"""

    # === Not Defined Cases ===
    def test_empty_expected_rule(self):
        """Should return 'Not Defined' when expected_rule is empty"""
        test_result = {
            'expected_rule': '',
            'rule_match': False
        }
        assert format_rule_match_status(test_result) == '⚠️ Not Defined'

    def test_na_expected_rule(self):
        """Should return 'Not Defined' when expected_rule is 'N/A'"""
        test_result = {
            'expected_rule': 'N/A',
            'rule_match': False
        }
        assert format_rule_match_status(test_result) == '⚠️ Not Defined'

    def test_missing_expected_rule(self):
        """Should return 'Not Defined' when expected_rule key is missing"""
        test_result = {
            'rule_match': False
        }
        assert format_rule_match_status(test_result) == '⚠️ Not Defined'

    def test_none_expected_rule(self):
        """Should return 'Not Defined' when expected_rule is None"""
        test_result = {
            'expected_rule': None,
            'rule_match': False
        }
        assert format_rule_match_status(test_result) == '⚠️ Not Defined'

    # === Match Cases ===
    def test_rule_match_true(self):
        """Should return 'Match' when rule_match is True"""
        test_result = {
            'expected_rule': '[NGINX SQLi] Advanced SQL Injection',
            'rule_match': True
        }
        assert format_rule_match_status(test_result) == '✅ Match'

    def test_rule_match_true_simple_rule(self):
        """Should return 'Match' for simple rule name with match"""
        test_result = {
            'expected_rule': 'SQL Injection Attempt',
            'rule_match': True
        }
        assert format_rule_match_status(test_result) == '✅ Match'

    # === Mismatch Cases ===
    def test_rule_match_false(self):
        """Should return 'Mismatch' when rule_match is False and expected_rule defined"""
        test_result = {
            'expected_rule': '[NGINX SQLi] Advanced SQL Injection',
            'rule_match': False
        }
        assert format_rule_match_status(test_result) == '❌ Mismatch'

    def test_rule_match_missing_defaults_false(self):
        """Should return 'Mismatch' when rule_match key is missing (defaults to False)"""
        test_result = {
            'expected_rule': '[NGINX SQLi] Advanced SQL Injection'
        }
        assert format_rule_match_status(test_result) == '❌ Mismatch'

    # === Edge Cases ===
    def test_empty_dict(self):
        """Should handle empty dictionary gracefully"""
        test_result = {}
        assert format_rule_match_status(test_result) == '⚠️ Not Defined'

    def test_whitespace_only_expected_rule(self):
        """Should treat whitespace-only expected_rule as empty"""
        # Note: The function checks for empty string but not whitespace
        # This test documents current behavior
        test_result = {
            'expected_rule': '   ',
            'rule_match': False
        }
        # Whitespace is truthy, so it goes to Mismatch path
        assert format_rule_match_status(test_result) == '❌ Mismatch'

    def test_rule_match_true_with_na(self):
        """Should return 'Not Defined' even if rule_match is True but expected_rule is N/A"""
        # This tests that expected_rule check takes precedence
        test_result = {
            'expected_rule': 'N/A',
            'rule_match': True
        }
        assert format_rule_match_status(test_result) == '⚠️ Not Defined'


class TestFormatRuleMatchStatusIntegration:
    """Integration tests with realistic test result structures"""

    def test_detection_with_match(self):
        """Test result where detection matched expected rule"""
        test_result = {
            'pattern_id': 'SQLI_TIME_001',
            'detected': True,
            'expected_rule': '[NGINX SQLi] Advanced SQL Injection Attempt',
            'rule_match': True,
            'matched_rule': '[NGINX SQLi] Advanced SQL Injection Attempt'
        }
        assert format_rule_match_status(test_result) == '✅ Match'

    def test_detection_with_mismatch(self):
        """Test result where detection didn't match expected rule"""
        test_result = {
            'pattern_id': 'XXE_ENTITY_001',
            'detected': True,
            'expected_rule': '[NGINX SQLi] Advanced SQL Injection Attempt',
            'rule_match': False,
            'matched_rule': '[NGINX XXE Attack] DOCTYPE/ENTITY injection'
        }
        assert format_rule_match_status(test_result) == '❌ Mismatch'

    def test_no_detection_expected(self):
        """Test result where no detection was expected (evasion test)"""
        test_result = {
            'pattern_id': 'CMD_ENC_003',
            'detected': False,
            'expected_detection': False,
            'expected_rule': '',
            'rule_match': False,
            'matched_rule': None
        }
        assert format_rule_match_status(test_result) == '⚠️ Not Defined'

    def test_detection_without_expected_rule(self):
        """Test result where rule was detected but expected_rule not defined"""
        test_result = {
            'pattern_id': 'OTHER_001',
            'detected': True,
            'expected_rule': '',
            'rule_match': False,
            'matched_rule': 'Some Detected Rule'
        }
        assert format_rule_match_status(test_result) == '⚠️ Not Defined'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
