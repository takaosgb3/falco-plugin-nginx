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
import html
import re
from pathlib import Path
from typing import Dict, List, Literal, Optional
from datetime import datetime, timezone

# ============================================
# Keyword Highlighting Functions (Issue #17)
# ============================================

def highlight_keywords_in_text(
    text: str,
    keywords: List[str],
    format: Literal["text", "html"] = "text"
) -> str:
    """
    Highlight keywords in text with visual markers

    Issue #17: Fluorescent yellow highlighting for keyword visibility
    Based on: PRIVATE repo Issue #706 implementation

    Args:
        text: Target text
        keywords: List of keywords to highlight
        format: "text" (>>> <<< markers) or "html" (<mark> tag, fluorescent yellow)

    Returns:
        Highlighted text
    """
    if not keywords or not text:
        return text

    result = text

    # HTML format: escape HTML first, then apply highlighting
    if format == "html":
        result = html.escape(result)

        def replace_func_html(match):
            return f'<mark style="background-color: #FFFF00; padding: 1px 3px;">{match.group(0)}</mark>'

        for keyword in keywords:
            # Escape keyword for HTML as well
            escaped_keyword = html.escape(keyword)
            pattern = re.compile(re.escape(escaped_keyword), re.IGNORECASE)
            result = pattern.sub(replace_func_html, result)
    else:
        # Text format: >>> keyword <<< markers
        def replace_func_text(match):
            return f">>> {match.group(0)} <<<"

        for keyword in keywords:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            result = pattern.sub(replace_func_text, result)

    return result


def wrap_highlighted_text_as_html(
    highlighted_text: str,
    title: str = "",
    use_pre: bool = True
) -> str:
    """
    Wrap highlighted text as a complete HTML document

    Issue #17: HTML document for Allure attachment
    Based on: PRIVATE repo Issue #706, #708 implementation

    Args:
        highlighted_text: Output from highlight_keywords_in_text(format="html")
        title: HTML document title (optional)
        use_pre: Use <pre> tag (True) or <div> (False)

    Returns:
        Complete HTML document
    """
    title_html = f"<h3>{html.escape(title)}</h3>" if title else ""

    if use_pre:
        content_html = f"<pre>{highlighted_text}</pre>"
    else:
        content_html = f"<div class='content'>{highlighted_text}</div>"

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        html, body {{
            margin: 0;
            padding: 0;
            height: auto;
            min-height: 600px;
            overflow: auto;
        }}
        body {{
            font-family: monospace;
            padding: 15px;
            background-color: #1a1a1a;
            color: #e0e0e0;
            line-height: 1.5;
        }}
        pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
            margin: 0;
            overflow: visible;
        }}
        .content {{
            overflow: visible;
        }}
        mark {{
            background-color: #FFFF00;
            color: #000;
            padding: 1px 3px;
            border-radius: 2px;
        }}
        h3 {{
            color: #4CAF50;
            margin: 0 0 15px 0;
        }}
    </style>
</head>
<body>
{title_html}
{content_html}
</body>
</html>"""


def extract_keywords_for_highlight(test_result: Dict, pattern_info: Optional[Dict] = None) -> List[str]:
    """
    Extract keywords for highlighting from test result and pattern info

    Args:
        test_result: Test result dictionary
        pattern_info: Pattern information dictionary (optional)

    Returns:
        List of keywords (payload, encoded)
    """
    keywords = []

    # From pattern_info (priority)
    if pattern_info:
        payload = pattern_info.get('payload', '')
        if payload:
            keywords.append(payload)

        encoded = pattern_info.get('encoded', '')
        if encoded and encoded != payload:
            keywords.append(encoded)

    # Fallback: from test_result if pattern_info doesn't have them
    if not keywords:
        payload = test_result.get('payload', '')
        if payload:
            keywords.append(payload)

        encoded = test_result.get('encoded', '')
        if encoded and encoded != payload:
            keywords.append(encoded)

    return keywords


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


def format_rule_match_status(test_result: Dict) -> str:
    """
    Format rule match status for display

    Issue #53: E2E ルールマッピング検証機能
    Extracted helper to eliminate code duplication

    Args:
        test_result: Test result dictionary containing:
            - expected_rule: Expected rule from pattern definition
            - rule_match: Boolean indicating if rules matched

    Returns:
        One of:
        - "✅ Match" if rule_match is True
        - "❌ Mismatch" if expected_rule is defined but no match
        - "⚠️ Not Defined" if expected_rule is empty or N/A
    """
    expected_rule = test_result.get('expected_rule', '')
    rule_match = test_result.get('rule_match', False)

    if not expected_rule or expected_rule == 'N/A':
        return '⚠️ Not Defined'
    if rule_match:
        return '✅ Match'
    return '❌ Mismatch'


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

def extract_sort_key(pattern_id: str) -> tuple:
    """
    Extract sort key from pattern ID for natural sorting.

    Examples:
        "SQLI_TIME_001" -> ("SQLI", "TIME", 1)
        "XSS_REFL_012" -> ("XSS", "REFL", 12)
        "CMD_BASIC_SEMICOLON_001" -> ("CMD", "BASIC_SEMICOLON", 1)

    Args:
        pattern_id: Pattern ID string

    Returns:
        Tuple for sorting (category, subcategory, number)
    """
    # Define category order for consistent sorting
    category_order = {
        'SQLI': 1,
        'XSS': 2,
        'PATH': 3,
        'CMD': 4,
        'MONGO': 5,
        'OTHER': 6
    }

    parts = pattern_id.split('_')

    # Extract category (first part)
    category = parts[0] if parts else ''
    cat_order = category_order.get(category, 99)

    # Extract numeric suffix
    num = 0
    if parts:
        last_part = parts[-1]
        if last_part.isdigit():
            num = int(last_part)

    # Subcategory is everything between category and number
    if len(parts) > 2:
        subcategory = '_'.join(parts[1:-1])
    elif len(parts) == 2:
        subcategory = ''
    else:
        subcategory = ''

    return (cat_order, subcategory, num)


def load_test_results(config) -> List[Dict]:
    """
    Load E2E test results from JSON file

    Args:
        config: pytest config object

    Returns:
        List of test results (sorted by pattern ID for consistent ordering)
    """
    test_results_path = Path(config.test_results)

    if not test_results_path.exists():
        raise FileNotFoundError(f"Test results not found: {test_results_path}")

    with open(test_results_path, 'r', encoding='utf-8') as f:
        results = json.load(f)

    # Sort results by pattern ID for consistent ordering in Allure report
    # Order: SQLI -> XSS -> PATH -> CMD -> MONGO/OTHER, then by number
    results.sort(key=lambda r: extract_sort_key(r.get('pattern_id', '')))

    return results


# ============================================
# Test Suite
# ============================================

def pytest_generate_tests(metafunc):
    """
    Dynamically generate test cases for each E2E test result.

    Test IDs are prefixed with zero-padded numbers (001_, 002_, etc.)
    to ensure correct ordering in Allure Suites view, which sorts
    alphabetically by default.
    """
    if 'test_result' in metafunc.fixturenames:
        results = load_test_results(metafunc.config)
        # Add numeric prefix for Allure UI sorting (e.g., "001_SQLI_BOOL_001")
        ids = [f"{i+1:03d}_{r['pattern_id']}" for i, r in enumerate(results)]
        metafunc.parametrize('test_result', results, ids=ids)


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

## Test Execution Results

- **Status**: `{status.upper()}`
- **Detection Count**: {format_detection_count(test_result)}
- **Latency**: {format_latency(test_result)}
- **Timestamp**: {format_timestamp(test_result.get('detected_at'))}

## Rule Mapping

| Item | Value |
|------|-------|
| **Expected Rule** | `{test_result.get('expected_rule', 'N/A')}` |
| **Matched Rule** | `{test_result.get('matched_rule', 'N/A')}` |
| **Rule Match** | {format_rule_match_status(test_result)} |

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

### Rule Mapping

| Item | Value |
|------|-------|
| **Expected Rule** | `{test_result.get('expected_rule', 'N/A')}` |
| **Matched Rule** | `{test_result.get('matched_rule', 'N/A')}` |
| **Rule Match** | {format_rule_match_status(test_result)} |

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
    # Step 2: Log Files (with Highlighting - Issue #17)
    # ========================================
    # Extract keywords for highlighting
    highlight_keywords = extract_keywords_for_highlight(test_result, pattern_info)

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
                    log_content = "\n".join(filtered_lines)

                    # Issue #17: Apply fluorescent yellow highlighting
                    if highlight_keywords:
                        highlighted_log = highlight_keywords_in_text(log_content, highlight_keywords, format="html")
                        html_content = wrap_highlighted_text_as_html(highlighted_log, "falco.log (Detected)")
                        allure.attach(
                            html_content,
                            name="falco.log (highlighted)",
                            attachment_type=allure.attachment_type.HTML
                        )
                    else:
                        allure.attach(
                            log_content,
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
                    log_content = "\n".join(filtered_lines)

                    # Issue #17: Apply fluorescent yellow highlighting
                    if highlight_keywords:
                        highlighted_log = highlight_keywords_in_text(log_content, highlight_keywords, format="html")
                        html_content = wrap_highlighted_text_as_html(highlighted_log, "nginx access.log")
                        allure.attach(
                            html_content,
                            name="nginx access.log (highlighted)",
                            attachment_type=allure.attachment_type.HTML
                        )
                    else:
                        allure.attach(
                            log_content,
                            name="nginx access.log (filtered)",
                            attachment_type=allure.attachment_type.TEXT
                        )

    # ========================================
    # Step 3: Detection Evidence (with Highlighting - Issue #17)
    # ========================================
    evidence = test_result.get('evidence', 'No evidence recorded')
    if evidence and evidence != 'No evidence recorded' and highlight_keywords:
        with allure.step("Detection Evidence (Highlighted)"):
            highlighted_evidence = highlight_keywords_in_text(evidence, highlight_keywords, format="html")
            evidence_html = wrap_highlighted_text_as_html(
                highlighted_evidence,
                "Detection Evidence (Falco Log Entry)"
            )
            allure.attach(
                evidence_html,
                name="Detection Evidence (HTML)",
                attachment_type=allure.attachment_type.HTML
            )

    # ========================================
    # Step: Rule Mapping Verification (Issue #53)
    # ========================================
    with allure.step("Rule Mapping Verification"):
        expected_rule = test_result.get('expected_rule', 'N/A')
        matched_rule = test_result.get('matched_rule', 'N/A')
        match_status = format_rule_match_status(test_result)

        mapping_summary = f"""
Expected Rule: {expected_rule}
Matched Rule: {matched_rule}
Rule Match: {match_status}
        """

        allure.attach(
            mapping_summary.strip(),
            name="Rule Mapping",
            attachment_type=allure.attachment_type.TEXT
        )

    # ========================================
    # Step 4: Verification Result
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
