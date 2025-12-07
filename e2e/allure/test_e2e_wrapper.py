#!/usr/bin/env python3
"""
E2E Test Results Wrapper for Allure Report (Public Repository Version)

Issue #3: E2E test workflow for falco-plugin-nginx
Based on: terraform/k6-e2e/allure-poc/test_e2e_wrapper.py (PRIVATE repo)

Simplified version for GitHub Actions:
- Removed rules_loader dependency (Falco rule details)
- Removed pattern_mapping dependency (Epic/Feature/Story)
- Focus on core functionality: test results display

Usage:
    pytest test_e2e_wrapper.py \
        --test-results=/path/to/test-results.json \
        --logs-dir=/path/to/logs \
        --alluredir=allure-results
"""

import json
import pytest
import allure
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timezone

# ============================================
# Helper Functions for Metrics Display
# ============================================

def format_detection_count(test_result: Dict) -> str:
    """
    Format detection count for display

    Args:
        test_result: Test result dictionary

    Returns:
        "1 / 1" or "0 / 1" format string
    """
    detected = test_result.get('detected', False)
    count = 1 if detected else 0
    return f"{count} / 1"


def format_timestamp(detected_at: Optional[int]) -> str:
    """
    Format timestamp for display

    Args:
        detected_at: Epoch milliseconds, or None

    Returns:
        UTC time string (HH:MM:SS.mmm UTC) or "N/A"
    """
    if detected_at is None:
        return "N/A"

    if detected_at < 0:
        return "N/A"

    try:
        dt = datetime.fromtimestamp(detected_at / 1000.0, tz=timezone.utc)
        return dt.strftime("%H:%M:%S.") + f"{int(detected_at % 1000):03d} UTC"
    except (ValueError, OSError, OverflowError):
        return "N/A"


def format_latency(test_result: Dict) -> str:
    """
    Format latency for display

    Args:
        test_result: Test result dictionary

    Returns:
        "583ms" or "N/A"
    """
    latency = test_result.get('latency_ms')

    if latency is None:
        return "N/A"

    detected_at = test_result.get('detected_at')
    sent_at = test_result.get('sent_at')

    if detected_at is not None and sent_at is not None:
        original_latency = detected_at - sent_at
        if original_latency < 0:
            abs_latency = abs(original_latency)
            if abs_latency < 100:
                return "< 0.1s"
            elif abs_latency < 1000:
                return "< 1s"
            else:
                return f"~{abs_latency}ms"

    return f"{latency}ms"


# ============================================
# Pattern Information Loading
# ============================================

_PATTERNS_CACHE: Optional[Dict] = None


def load_all_patterns() -> Dict:
    """
    Load pattern data from JSON files and cache

    Returns:
        Dictionary with pattern_id as key, pattern info as value
    """
    global _PATTERNS_CACHE

    if _PATTERNS_CACHE is not None:
        return _PATTERNS_CACHE

    try:
        current_dir = Path(__file__).parent
        patterns_dir = current_dir.parent / 'patterns'

        _PATTERNS_CACHE = {}

        # Load all category pattern files
        for pattern_file in patterns_dir.glob('*_patterns.json'):
            with open(pattern_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict) and 'patterns' in data:
                    for p in data['patterns']:
                        _PATTERNS_CACHE[p['id']] = p

        return _PATTERNS_CACHE

    except Exception as e:
        print(f"Error loading patterns: {e}")
        _PATTERNS_CACHE = {}
        return _PATTERNS_CACHE


def load_pattern_info(pattern_id: str) -> Optional[Dict]:
    """
    Load pattern information by ID

    Args:
        pattern_id: Pattern ID (e.g., "PATH_ABS_001")

    Returns:
        Pattern information dictionary, or None if not found
    """
    patterns = load_all_patterns()
    return patterns.get(pattern_id)


# ============================================
# Test Data Loading
# ============================================

def load_test_results(config) -> List[Dict]:
    """
    Load E2E test results from JSON file

    Args:
        config: pytest config object

    Returns:
        List of test results
    """
    test_results_path = Path(config.test_results)

    if not test_results_path.exists():
        raise FileNotFoundError(f"Test results not found: {test_results_path}")

    with open(test_results_path, 'r', encoding='utf-8') as f:
        results = json.load(f)

    return results


# ============================================
# Test Suite
# ============================================

def pytest_generate_tests(metafunc):
    """
    Dynamically generate test cases for each E2E test result
    """
    if 'test_result' in metafunc.fixturenames:
        results = load_test_results(metafunc.config)
        metafunc.parametrize('test_result', results, ids=[r['pattern_id'] for r in results])


@pytest.mark.allure
def test_e2e_with_logs(request, test_result: Dict):
    """
    Process E2E test result and generate Allure report

    Args:
        request: pytest request fixture
        test_result: Single E2E test result
    """
    pattern_id = test_result['pattern_id']
    status = test_result.get('status', 'unknown')
    logs_dir = Path(request.config.logs_dir) if hasattr(request.config, 'logs_dir') else None

    # Load pattern information
    pattern_info = load_pattern_info(pattern_id)

    # Get expected rule information
    expected_rule = pattern_info.get('expected_rule', 'N/A') if pattern_info else 'N/A'
    actual_rule = test_result.get('rule_name', 'N/A')
    rule_id = pattern_info.get('rule_id', 'N/A') if pattern_info else 'N/A'

    # Check if expected rule matches actual rule (case-insensitive)
    rule_match_status = ""
    if expected_rule != 'N/A' and actual_rule and actual_rule != 'N/A':
        expected_lower = expected_rule.lower()
        actual_lower = actual_rule.lower()
        if expected_lower in actual_lower or actual_lower in expected_lower:
            rule_match_status = "MATCH"
        else:
            rule_match_status = "MISMATCH"

    # Build description
    if pattern_info:
        description = f"""
## Attack Pattern Information

| Item | Value |
|------|-------|
| **Pattern ID** | `{pattern_id}` |
| **Name** | {pattern_info.get('name', 'N/A')} |
| **Category** | {pattern_info.get('category', 'N/A').upper()} |
| **Subcategory** | {pattern_info.get('subcategory', 'N/A')} |
| **Severity** | `{pattern_info.get('severity', 'medium').upper()}` |

## Attack Details

- **Payload**: `{pattern_info.get('payload', 'N/A')}`
- **Encoded**: `{pattern_info.get('encoded', 'N/A')}`
- **Expected Detection**: {'Yes' if pattern_info.get('expected_detection') else 'No'}

## Rule Mapping

| Item | Value |
|------|-------|
| **Rule ID** | `{rule_id}` |
| **Expected Rule** | {expected_rule} |
| **Actual Rule** | {actual_rule if actual_rule else 'N/A'} |
| **Match Status** | {'`' + rule_match_status + '`' if rule_match_status else 'N/A'} |

## Test Execution Results

- **Status**: `{status.upper()}`
- **Detection Count**: {format_detection_count(test_result)}
- **Latency**: {format_latency(test_result)}
- **Timestamp**: {format_timestamp(test_result.get('detected_at'))}

## Detection Evidence

{'**Rule Name**: ' + test_result.get('rule_name', 'N/A') if test_result.get('rule_name') else ''}

**Falco Log Entry**:
```
{test_result.get('evidence', 'No evidence recorded')}
```
"""
    else:
        description = f"""
## Pattern Information Unavailable

**Pattern ID**: `{pattern_id}`

Pattern details could not be loaded.

### Test Results

- **Status**: `{status.upper()}`
- **Detection**: {format_detection_count(test_result)}
- **Latency**: {format_latency(test_result)}

### Detection Evidence

```
{test_result.get('evidence', 'No evidence recorded')}
```
"""

    allure.dynamic.description(description.strip())

    # Set Allure metadata
    category = pattern_info.get('category', 'unknown') if pattern_info else 'unknown'
    allure.dynamic.epic("E2E Security Tests")
    allure.dynamic.feature(category.upper())
    allure.dynamic.story(pattern_id)
    allure.dynamic.severity("critical")

    # ========================================
    # Step 1: k6 Test Execution Result
    # ========================================
    with allure.step("k6 Test Execution Result"):
        allure.attach(
            json.dumps(test_result, indent=2, ensure_ascii=False),
            name=f"{pattern_id}-result.json",
            attachment_type=allure.attachment_type.JSON
        )

        summary = f"""
        Pattern ID: {pattern_id}
        Status: {status}
        Latency: {format_latency(test_result)}
        Detection: {format_detection_count(test_result)}
        Rule: {test_result.get('rule_name', 'N/A')}
        """

        allure.attach(
            summary.strip(),
            name="Test Summary",
            attachment_type=allure.attachment_type.TEXT
        )

    # ========================================
    # Step 2: Log Files
    # ========================================
    if logs_dir:
        with allure.step("Log Files"):
            # Falco log
            falco_log = logs_dir / "falco.log"
            if falco_log.exists():
                content = falco_log.read_text(encoding='utf-8', errors='replace')
                # Filter by pattern_id
                filtered_lines = [
                    line for line in content.splitlines()
                    if pattern_id in line
                ]
                if filtered_lines:
                    allure.attach(
                        "\n".join(filtered_lines),
                        name="falco.log (filtered)",
                        attachment_type=allure.attachment_type.TEXT
                    )

            # nginx access log
            nginx_log = logs_dir / "nginx-access.log"
            if nginx_log.exists():
                content = nginx_log.read_text(encoding='utf-8', errors='replace')
                # Filter by pattern_id
                filtered_lines = [
                    line for line in content.splitlines()
                    if pattern_id in line
                ]
                if filtered_lines:
                    allure.attach(
                        "\n".join(filtered_lines),
                        name="nginx access.log (filtered)",
                        attachment_type=allure.attachment_type.TEXT
                    )

    # ========================================
    # Step 3: Verification Result
    # ========================================
    with allure.step("Verification Result"):
        if status == 'passed':
            result_message = f"Test passed: {pattern_id}"
            allure.attach(
                result_message,
                name="Test Result",
                attachment_type=allure.attachment_type.TEXT
            )
        else:
            error_message = test_result.get('error_message', 'Unknown error')
            result_message = f"Test failed: {pattern_id}\nReason: {error_message}"
            allure.attach(
                result_message,
                name="Test Result",
                attachment_type=allure.attachment_type.TEXT
            )

        # pytest assertion
        assert status == 'passed', f"Test {pattern_id} failed: {error_message if status != 'passed' else ''}"
