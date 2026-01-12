#!/usr/bin/env python3
"""
Generate Rule Mapping Trend Data for Allure Categories Trend

Issue #59: Add Rule Mapping Trend graph to Allure Report

This script calculates Rule Mapping statistics from test-results.json and
generates/updates categories-trend.json for Allure's Categories Trend graph.

Usage:
    python generate_rule_mapping_trend.py \
        --test-results results/test-results.json \
        --run-number 100 \
        --report-url "https://example.com/100/" \
        --history-input allure-results/history/categories-trend.json \
        --history-output allure-results/history/categories-trend.json \
        --max-history 10
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Rule Mapping status categories (matching format_rule_match_status in test_e2e_wrapper.py)
CATEGORY_MATCH = "Rule Match"
CATEGORY_MISMATCH = "Rule Mismatch"
CATEGORY_EXPECTED_NOT_DETECTED = "Expected Not Detected"
CATEGORY_NOT_DEFINED = "Not Defined"


def calculate_rule_mapping_status(test_result: Dict) -> str:
    """
    Calculate Rule Mapping status for a single test result.

    This logic mirrors format_rule_match_status() in test_e2e_wrapper.py

    Args:
        test_result: Test result dictionary

    Returns:
        One of: CATEGORY_MATCH, CATEGORY_MISMATCH,
                CATEGORY_EXPECTED_NOT_DETECTED, CATEGORY_NOT_DEFINED
    """
    # Check for negative test case first (Issue #58)
    expected_detection = test_result.get('expected_detection', True)
    if expected_detection is False:
        return CATEGORY_EXPECTED_NOT_DETECTED

    expected_rule = test_result.get('expected_rule', '')
    rule_match = test_result.get('rule_match') is True

    if not expected_rule or expected_rule == 'N/A':
        return CATEGORY_NOT_DEFINED
    if rule_match:
        return CATEGORY_MATCH
    return CATEGORY_MISMATCH


def calculate_statistics(test_results: List[Dict]) -> Dict[str, int]:
    """
    Calculate Rule Mapping statistics from test results.

    Args:
        test_results: List of test result dictionaries

    Returns:
        Dictionary with category counts:
        {
            "Rule Match": 95,
            "Rule Mismatch": 0,
            "Expected Not Detected": 3,
            "Not Defined": 2
        }
    """
    stats = {
        CATEGORY_MATCH: 0,
        CATEGORY_MISMATCH: 0,
        CATEGORY_EXPECTED_NOT_DETECTED: 0,
        CATEGORY_NOT_DEFINED: 0
    }

    for result in test_results:
        status = calculate_rule_mapping_status(result)
        stats[status] += 1

    return stats


def create_trend_entry(
    run_number: int,
    report_url: str,
    stats: Dict[str, int]
) -> Dict:
    """
    Create a single trend entry for categories-trend.json

    Args:
        run_number: GitHub Actions run number
        report_url: URL to the Allure report
        stats: Rule Mapping statistics

    Returns:
        Trend entry dictionary
    """
    return {
        "buildOrder": run_number,
        "reportName": f"E2E Tests #{run_number}",
        "reportUrl": report_url,
        "data": stats
    }


def merge_trend_history(
    new_entry: Dict,
    existing_history: List[Dict],
    max_history: int = 10
) -> List[Dict]:
    """
    Merge new trend entry into existing history, keeping only the last N entries.

    Args:
        new_entry: New trend entry to add
        existing_history: Existing history entries
        max_history: Maximum number of entries to keep

    Returns:
        Updated history list (newest first)
    """
    # Add new entry at the beginning
    updated = [new_entry] + existing_history

    # Remove duplicates (same buildOrder)
    seen = set()
    deduplicated = []
    for entry in updated:
        build_order = entry.get('buildOrder')
        if build_order not in seen:
            seen.add(build_order)
            deduplicated.append(entry)

    # Sort by buildOrder descending (newest first)
    deduplicated.sort(key=lambda x: x.get('buildOrder', 0), reverse=True)

    # Keep only the last N entries
    return deduplicated[:max_history]


def main():
    parser = argparse.ArgumentParser(
        description='Generate Rule Mapping Trend Data for Allure (Issue #59)'
    )
    parser.add_argument(
        '--test-results',
        required=True,
        help='Path to test-results.json'
    )
    parser.add_argument(
        '--run-number',
        type=int,
        required=True,
        help='GitHub Actions run number'
    )
    parser.add_argument(
        '--report-url',
        default='',
        help='URL to the Allure report'
    )
    parser.add_argument(
        '--history-input',
        help='Path to existing categories-trend.json (optional)'
    )
    parser.add_argument(
        '--history-output',
        required=True,
        help='Output path for updated categories-trend.json'
    )
    parser.add_argument(
        '--max-history',
        type=int,
        default=10,
        help='Maximum number of history entries to keep (default: 10)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(levelname)s: %(message)s'
    )

    # Load test results
    test_results_path = Path(args.test_results)
    if not test_results_path.exists():
        logger.error(f"Test results file not found: {args.test_results}")
        sys.exit(1)

    with open(test_results_path, 'r') as f:
        test_results = json.load(f)

    logger.info(f"Loaded {len(test_results)} test results")

    # Calculate statistics
    stats = calculate_statistics(test_results)
    logger.info(f"Rule Mapping Statistics: {stats}")

    # Create new trend entry
    new_entry = create_trend_entry(
        run_number=args.run_number,
        report_url=args.report_url,
        stats=stats
    )

    # Load existing history
    existing_history = []
    if args.history_input:
        history_path = Path(args.history_input)
        if history_path.exists():
            try:
                with open(history_path, 'r') as f:
                    existing_history = json.load(f)
                logger.info(f"Loaded {len(existing_history)} existing history entries")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load existing history: {e}")

    # Merge with existing history
    updated_history = merge_trend_history(
        new_entry=new_entry,
        existing_history=existing_history,
        max_history=args.max_history
    )

    # Write output
    output_path = Path(args.history_output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(updated_history, f, indent=2)

    logger.info(f"Written {len(updated_history)} history entries to {args.history_output}")

    # Print summary
    total = sum(stats.values())
    match_rate = (stats[CATEGORY_MATCH] / total * 100) if total > 0 else 0

    print(f"\n{'='*50}")
    print("Rule Mapping Trend Data Generated (Issue #59)")
    print(f"{'='*50}")
    print(f"Run Number: {args.run_number}")
    print(f"Total Patterns: {total}")
    print(f"  - {CATEGORY_MATCH}: {stats[CATEGORY_MATCH]}")
    print(f"  - {CATEGORY_MISMATCH}: {stats[CATEGORY_MISMATCH]}")
    print(f"  - {CATEGORY_EXPECTED_NOT_DETECTED}: {stats[CATEGORY_EXPECTED_NOT_DETECTED]}")
    print(f"  - {CATEGORY_NOT_DEFINED}: {stats[CATEGORY_NOT_DEFINED]}")
    print(f"Match Rate: {match_rate:.1f}%")
    print(f"{'='*50}")


if __name__ == '__main__':
    main()
