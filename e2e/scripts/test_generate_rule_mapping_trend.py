#!/usr/bin/env python3
"""
Unit tests for generate_rule_mapping_trend.py

Issue #59: Add Rule Mapping Trend graph to Allure Report
"""

import pytest
from generate_rule_mapping_trend import (
    calculate_rule_mapping_status,
    calculate_statistics,
    create_trend_entry,
    merge_trend_history,
    CATEGORY_MATCH,
    CATEGORY_MISMATCH,
    CATEGORY_EXPECTED_NOT_DETECTED,
    CATEGORY_NOT_DEFINED
)


class TestCalculateRuleMappingStatus:
    """Tests for calculate_rule_mapping_status()"""

    def test_rule_match_true_returns_match(self):
        """Should return CATEGORY_MATCH when rule_match is True"""
        result = {
            'expected_rule': 'Some Rule',
            'rule_match': True
        }
        assert calculate_rule_mapping_status(result) == CATEGORY_MATCH

    def test_rule_match_false_returns_mismatch(self):
        """Should return CATEGORY_MISMATCH when rule_match is False"""
        result = {
            'expected_rule': 'Some Rule',
            'rule_match': False
        }
        assert calculate_rule_mapping_status(result) == CATEGORY_MISMATCH

    def test_empty_expected_rule_returns_not_defined(self):
        """Should return CATEGORY_NOT_DEFINED when expected_rule is empty"""
        result = {
            'expected_rule': '',
            'rule_match': False
        }
        assert calculate_rule_mapping_status(result) == CATEGORY_NOT_DEFINED

    def test_na_expected_rule_returns_not_defined(self):
        """Should return CATEGORY_NOT_DEFINED when expected_rule is N/A"""
        result = {
            'expected_rule': 'N/A',
            'rule_match': False
        }
        assert calculate_rule_mapping_status(result) == CATEGORY_NOT_DEFINED

    def test_expected_detection_false_returns_expected_not_detected(self):
        """Should return CATEGORY_EXPECTED_NOT_DETECTED when expected_detection is False"""
        result = {
            'expected_detection': False,
            'expected_rule': '',
            'rule_match': False
        }
        assert calculate_rule_mapping_status(result) == CATEGORY_EXPECTED_NOT_DETECTED

    def test_expected_detection_false_takes_precedence(self):
        """expected_detection: false should take precedence over other conditions"""
        result = {
            'expected_detection': False,
            'expected_rule': 'Some Rule',
            'rule_match': True
        }
        assert calculate_rule_mapping_status(result) == CATEGORY_EXPECTED_NOT_DETECTED

    def test_missing_expected_detection_defaults_to_true(self):
        """Missing expected_detection should default to True (normal flow)"""
        result = {
            'expected_rule': 'Some Rule',
            'rule_match': True
        }
        assert calculate_rule_mapping_status(result) == CATEGORY_MATCH


class TestCalculateStatistics:
    """Tests for calculate_statistics()"""

    def test_empty_results(self):
        """Should return zero counts for empty results"""
        stats = calculate_statistics([])
        assert stats[CATEGORY_MATCH] == 0
        assert stats[CATEGORY_MISMATCH] == 0
        assert stats[CATEGORY_EXPECTED_NOT_DETECTED] == 0
        assert stats[CATEGORY_NOT_DEFINED] == 0

    def test_all_match(self):
        """Should count all as match when all rules match"""
        results = [
            {'expected_rule': 'Rule A', 'rule_match': True},
            {'expected_rule': 'Rule B', 'rule_match': True},
            {'expected_rule': 'Rule C', 'rule_match': True}
        ]
        stats = calculate_statistics(results)
        assert stats[CATEGORY_MATCH] == 3
        assert stats[CATEGORY_MISMATCH] == 0

    def test_mixed_statuses(self):
        """Should correctly count mixed statuses"""
        results = [
            {'expected_rule': 'Rule A', 'rule_match': True},  # Match
            {'expected_rule': 'Rule B', 'rule_match': False},  # Mismatch
            {'expected_detection': False, 'expected_rule': '', 'rule_match': False},  # Expected Not Detected
            {'expected_rule': '', 'rule_match': False}  # Not Defined
        ]
        stats = calculate_statistics(results)
        assert stats[CATEGORY_MATCH] == 1
        assert stats[CATEGORY_MISMATCH] == 1
        assert stats[CATEGORY_EXPECTED_NOT_DETECTED] == 1
        assert stats[CATEGORY_NOT_DEFINED] == 1

    def test_realistic_distribution(self):
        """Test with realistic 100-pattern distribution"""
        results = []
        # 95 matches
        results.extend([{'expected_rule': f'Rule {i}', 'rule_match': True} for i in range(95)])
        # 0 mismatches
        # 3 expected not detected
        results.extend([{'expected_detection': False, 'expected_rule': '', 'rule_match': False} for _ in range(3)])
        # 2 not defined
        results.extend([{'expected_rule': '', 'rule_match': False} for _ in range(2)])

        stats = calculate_statistics(results)
        assert stats[CATEGORY_MATCH] == 95
        assert stats[CATEGORY_MISMATCH] == 0
        assert stats[CATEGORY_EXPECTED_NOT_DETECTED] == 3
        assert stats[CATEGORY_NOT_DEFINED] == 2


class TestCreateTrendEntry:
    """Tests for create_trend_entry()"""

    def test_creates_valid_entry(self):
        """Should create a valid trend entry"""
        stats = {
            CATEGORY_MATCH: 95,
            CATEGORY_MISMATCH: 0,
            CATEGORY_EXPECTED_NOT_DETECTED: 3,
            CATEGORY_NOT_DEFINED: 2
        }
        entry = create_trend_entry(
            run_number=100,
            report_url='https://example.com/100/',
            stats=stats
        )

        assert entry['buildOrder'] == 100
        assert entry['reportName'] == 'E2E Tests #100'
        assert entry['reportUrl'] == 'https://example.com/100/'
        assert entry['data'] == stats


class TestMergeTrendHistory:
    """Tests for merge_trend_history()"""

    def test_empty_history(self):
        """Should work with empty existing history"""
        new_entry = {'buildOrder': 100, 'data': {'Match': 95}}
        result = merge_trend_history(new_entry, [])
        assert len(result) == 1
        assert result[0]['buildOrder'] == 100

    def test_adds_to_history(self):
        """Should add new entry to existing history"""
        new_entry = {'buildOrder': 102, 'data': {'Match': 97}}
        existing = [
            {'buildOrder': 101, 'data': {'Match': 96}},
            {'buildOrder': 100, 'data': {'Match': 95}}
        ]
        result = merge_trend_history(new_entry, existing)
        assert len(result) == 3
        assert result[0]['buildOrder'] == 102  # Newest first

    def test_respects_max_history(self):
        """Should keep only max_history entries"""
        new_entry = {'buildOrder': 110, 'data': {'Match': 99}}
        existing = [{'buildOrder': i, 'data': {'Match': i}} for i in range(109, 99, -1)]
        result = merge_trend_history(new_entry, existing, max_history=5)
        assert len(result) == 5
        assert result[0]['buildOrder'] == 110
        assert result[-1]['buildOrder'] == 106

    def test_deduplicates_by_build_order(self):
        """Should remove duplicates with same buildOrder"""
        new_entry = {'buildOrder': 100, 'data': {'Match': 98}}  # Updated
        existing = [
            {'buildOrder': 100, 'data': {'Match': 95}},  # Old
            {'buildOrder': 99, 'data': {'Match': 94}}
        ]
        result = merge_trend_history(new_entry, existing)
        assert len(result) == 2
        # New entry should be kept (first occurrence wins)
        assert result[0]['buildOrder'] == 100
        assert result[0]['data']['Match'] == 98

    def test_sorts_descending(self):
        """Should sort by buildOrder descending"""
        new_entry = {'buildOrder': 50, 'data': {}}
        existing = [
            {'buildOrder': 100, 'data': {}},
            {'buildOrder': 75, 'data': {}},
            {'buildOrder': 25, 'data': {}}
        ]
        result = merge_trend_history(new_entry, existing)
        build_orders = [e['buildOrder'] for e in result]
        assert build_orders == [100, 75, 50, 25]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
