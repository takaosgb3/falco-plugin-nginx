#!/usr/bin/env python3
"""
Batch Analyzer for E2E Test Results (Public Repository Version)

Issue #3: E2E test workflow for falco-plugin-nginx
Based on: terraform/k6-e2e/scripts/batch_analyzer.py (PRIVATE repo)

Modifications for GitHub Actions environment:
- Local file paths only (no SSH)
- Environment variable configuration
- GitHub Actions compatible logging
"""

import os
import re
import json
import argparse
import logging
import sys
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

# ========================================
# Constants
# ========================================

# test_id extraction pattern
# Pattern format: PATTERN_ID-TIMESTAMP-RANDOM
TEST_ID_PATTERN = re.compile(r'test_id=([A-Z0-9_]+-\d{13}-[a-z0-9]+)')

# Log format detection patterns
FILE_OUTPUT_PATTERN = re.compile(r'^\d{2}:\d{2}:\d{2}')
SYSLOG_PATTERN = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')

# Timestamp extraction patterns
FILE_OUTPUT_TIMESTAMP = re.compile(r'^(\d{2}:\d{2}:\d{2}\.\d+)')
SYSLOG_TIMESTAMP = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')

# Rule name extraction pattern
RULE_NAME_PATTERN = re.compile(r'(?:Notice|Info|Warning|Error|Critical|Alert|Emergency)\s+(.+?)(?:\s+\(|$)')

# Latency calculation thresholds
LATENCY_SUBSECOND_THRESHOLD_MS = 60000  # 1 minute
MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000  # 86,400,000ms

logger = logging.getLogger(__name__)

# ========================================
# Helper Functions
# ========================================

def extract_pattern_id(test_id: str) -> str:
    """
    Extract pattern_id from test_id

    Examples:
        SQLI_TIME_001-1732267890123-abc123 → SQLI_TIME_001
        XSS_DOM_BASED-1732267890123-7k9p2m → XSS_DOM_BASED
    """
    parts = test_id.rsplit('-', 2)
    if len(parts) == 3:
        return parts[0]
    return test_id


def normalize_rule_name(name: Optional[str]) -> str:
    """
    Normalize rule name for comparison by removing prefix and lowercasing

    Issue #53: E2E ルールマッピング検証機能

    Examples:
        "[NGINX SQLi] Advanced SQL Injection Attempt" → "advanced sql injection attempt"
        "[NGINX XSS] Cross-Site Scripting" → "cross-site scripting"
        "Simple Rule Name" → "simple rule name"
    """
    if not name:
        return ""
    # Remove [NGINX XXX] prefix if present
    match = re.match(r'\[NGINX [^\]]+\]\s*(.+)', name)
    return match.group(1).strip().lower() if match else name.strip().lower()


def compare_rules(expected_rule: str, rule_name: str) -> bool:
    """
    Compare expected rule with actual fired rule

    Issue #53: E2E ルールマッピング検証機能

    Matching logic:
    1. Exact match
    2. Normalized match (case-insensitive, without prefix)
    3. Substring match (if normalized expected >= 10 chars and contained in actual)

    Args:
        expected_rule: Expected rule name from pattern definition
        rule_name: Actual rule name from Falco detection

    Returns:
        True if rules match, False otherwise
    """
    if not expected_rule or not rule_name:
        return False

    # Exact match
    if expected_rule == rule_name:
        return True

    # Normalized match
    norm_expected = normalize_rule_name(expected_rule)
    norm_actual = normalize_rule_name(rule_name)

    if norm_expected == norm_actual:
        return True

    # Substring match for longer rule names
    if len(norm_expected) >= 10 and norm_expected in norm_actual:
        return True

    return False


def parse_timestamp_to_ms(timestamp_str: str, log_format: str) -> Optional[int]:
    """
    Convert log timestamp to milliseconds

    Args:
        timestamp_str: Timestamp string
        log_format: 'file_output' or 'syslog'

    Returns:
        Millisecond timestamp (based on today's date)
    """
    try:
        now = datetime.now()

        if log_format == 'file_output':
            # "08:49:52.607913000" format
            parts = timestamp_str.split('.')
            time_parts = parts[0].split(':')
            hour = int(time_parts[0])
            minute = int(time_parts[1])
            second = int(time_parts[2])

            if len(parts) > 1:
                nano_str = parts[1][:9].ljust(9, '0')
                ms = int(nano_str[:3])
            else:
                ms = 0

            dt = now.replace(hour=hour, minute=minute, second=second, microsecond=ms * 1000)
            return int(dt.timestamp() * 1000)

        elif log_format == 'syslog':
            # "Nov 22 08:49:52" format
            parts = timestamp_str.split()
            month_name = parts[0]
            day = int(parts[1])
            time_parts = parts[2].split(':')

            months = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                     'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
            month = months.get(month_name, now.month)

            dt = now.replace(month=month, day=day,
                           hour=int(time_parts[0]),
                           minute=int(time_parts[1]),
                           second=int(time_parts[2]),
                           microsecond=0)
            return int(dt.timestamp() * 1000)

    except Exception as e:
        logger.warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
        return None


# ========================================
# Main Class
# ========================================

class BatchAnalyzer:
    """
    Batch processing analyzer for detection results
    """

    def __init__(self, patterns_dir: str, wait_time: int = None):
        """
        Initialize analyzer

        Args:
            patterns_dir: Directory containing pattern JSON files
            wait_time: Falco processing wait time (seconds)
                       Uses BATCH_WAIT_TIME env var or default 60
        """
        self.wait_time = wait_time or int(os.environ.get('BATCH_WAIT_TIME', 60))
        self.patterns = []
        self.pattern_map = {}

        # Load all pattern files from directory
        patterns_path = Path(patterns_dir)
        if patterns_path.is_file():
            # Single file mode (all_patterns.json)
            self._load_pattern_file(patterns_path)
        else:
            # Directory mode (multiple category files)
            for pattern_file in patterns_path.glob('*_patterns.json'):
                self._load_pattern_file(pattern_file)

        logger.info(f"Loaded {len(self.patterns)} patterns total")
        logger.info(f"Wait time: {self.wait_time} seconds")

    def _load_pattern_file(self, filepath: Path):
        """Load patterns from a single JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
            if isinstance(data, dict) and 'patterns' in data:
                patterns = data['patterns']
            else:
                patterns = data

            for p in patterns:
                self.patterns.append(p)
                self.pattern_map[p['id']] = p

        logger.debug(f"Loaded patterns from {filepath.name}")

    def parse_falco_log(self, log_path: str) -> Dict[str, Dict]:
        """
        Parse falco.log and return detection info per test_id

        Args:
            log_path: Path to falco.log

        Returns:
            {
                "test_id": {
                    "detected": True,
                    "timestamp": "...",
                    "detected_at": 1732267890200,
                    "log_line": "...",
                    "rule_name": "..."
                },
                ...
            }
        """
        detections = {}

        if not os.path.exists(log_path):
            logger.warning(f"Log file not found: {log_path}")
            return detections

        with open(log_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                match = TEST_ID_PATTERN.search(line)
                if not match:
                    continue

                test_id = match.group(1)

                # Detect log format
                log_format = None
                timestamp_str = None

                if FILE_OUTPUT_PATTERN.match(line):
                    log_format = 'file_output'
                    ts_match = FILE_OUTPUT_TIMESTAMP.match(line)
                    if ts_match:
                        timestamp_str = ts_match.group(1)
                elif SYSLOG_PATTERN.match(line):
                    log_format = 'syslog'
                    ts_match = SYSLOG_TIMESTAMP.match(line)
                    if ts_match:
                        timestamp_str = ts_match.group(1)

                detected_at = None
                if timestamp_str and log_format:
                    detected_at = parse_timestamp_to_ms(timestamp_str, log_format)

                rule_name = None
                rule_match = RULE_NAME_PATTERN.search(line)
                if rule_match:
                    rule_name = rule_match.group(1).strip()

                detections[test_id] = {
                    "detected": True,
                    "timestamp": timestamp_str,
                    "detected_at": detected_at,
                    "log_line": line,
                    "rule_name": rule_name,
                    "log_format": log_format
                }

                logger.debug(f"Detected: {test_id} (rule: {rule_name})")

        logger.info(f"Parsed {len(detections)} detections from {log_path}")
        return detections

    def match_patterns(
        self,
        detections: Dict[str, Dict],
        test_ids: List[Dict]
    ) -> List[Dict]:
        """
        Match detection results with expected patterns

        Args:
            detections: Output from parse_falco_log()
            test_ids: List from test_ids.json

        Returns:
            List of pattern results
        """
        results = []

        for test_info in test_ids:
            test_id = test_info.get('test_id')
            pattern_id = test_info.get('pattern_id') or extract_pattern_id(test_id)
            sent_at = test_info.get('sent_at')
            category = test_info.get('category', '')

            pattern_data = self.pattern_map.get(pattern_id, {})
            if not category and pattern_data:
                category = pattern_data.get('category', '')

            # Get expected rule from pattern definition
            expected_rule = pattern_data.get('expected_rule', '')
            rule_id = pattern_data.get('rule_id', '')

            detection = detections.get(test_id, {})
            detected = detection.get('detected', False)
            detected_at = detection.get('detected_at')
            evidence = detection.get('log_line', '')
            rule_name = detection.get('rule_name', '')

            # Calculate latency
            latency_ms = None
            if detected and sent_at and detected_at:
                latency_ms = detected_at - sent_at
                if latency_ms < 0:
                    original_latency = latency_ms
                    if abs(latency_ms) < LATENCY_SUBSECOND_THRESHOLD_MS:
                        latency_ms = abs(latency_ms)
                        logger.debug(f"Adjusted sub-second negative latency for {test_id}: {original_latency}ms -> {latency_ms}ms")
                    else:
                        latency_ms += MILLISECONDS_PER_DAY
                        logger.debug(f"Adjusted midnight crossing latency for {test_id}: {original_latency}ms -> {latency_ms}ms")

            # Get expected_detection from pattern definition (default True for backward compatibility)
            # Pattern #A326: Properly handle expected_detection field
            expected_detection = pattern_data.get('expected_detection', True)

            # Issue #53: Calculate rule_match and matched_rule
            # rule_match: True if expected_rule matches actual rule_name
            # matched_rule: The actual rule that was matched (only if detected)
            rule_match = compare_rules(expected_rule, rule_name) if detected and expected_rule else False
            matched_rule = rule_name if detected else None

            result = {
                "pattern_id": pattern_id,
                "test_id": test_id,
                "category": category,
                "detected": detected,
                "expected_detection": expected_detection,
                "sent_at": sent_at,
                "detected_at": detected_at,
                "latency_ms": latency_ms,
                "evidence": evidence,
                "rule_name": rule_name,
                "expected_rule": expected_rule,
                "rule_id": rule_id,
                "rule_match": rule_match,
                "matched_rule": matched_rule
            }

            results.append(result)

            status = "✓" if detected else "✗"
            logger.debug(f"{status} {pattern_id}: detected={detected}, latency={latency_ms}ms")

        detected_count = sum(1 for r in results if r['detected'])
        logger.info(f"Matched {detected_count}/{len(results)} patterns")

        return results

    def generate_test_results(self, pattern_results: List[Dict]) -> List[Dict]:
        """
        Generate test-results.json format output

        Args:
            pattern_results: Output from match_patterns()

        Returns:
            List in test-results.json format
        """
        test_results = []

        for result in pattern_results:
            # Pattern #A326: Properly determine status based on expected_detection
            # | expected_detection | detected | status |
            # |--------------------|----------|--------|
            # | true               | true     | passed | (detected as expected)
            # | true               | false    | failed | (should detect but didn't)
            # | false              | true     | failed | (false positive - shouldn't detect but did)
            # | false              | false    | passed | (correctly not detected)
            expected_detection = result.get("expected_detection", True)
            detected = result["detected"]

            if expected_detection:
                status = "passed" if detected else "failed"
            else:
                status = "passed" if not detected else "failed"

            test_result = {
                "pattern_id": result["pattern_id"],
                "test_id": result["test_id"],
                "category": result["category"],
                "detected": result["detected"],
                "expected_detection": expected_detection,
                "latency_ms": result["latency_ms"],
                "evidence": result["evidence"],
                "rule_name": result.get("rule_name", ""),
                "expected_rule": result.get("expected_rule", ""),
                "rule_id": result.get("rule_id", ""),
                "rule_match": result.get("rule_match", False),
                "matched_rule": result.get("matched_rule"),
                "sent_at": result["sent_at"],
                "detected_at": result["detected_at"],
                "status": status
            }
            test_results.append(test_result)

        return test_results

    def analyze(
        self,
        falco_log_path: str,
        test_ids_path: str
    ) -> Tuple[List[Dict], Dict]:
        """
        Main analysis processing

        Args:
            falco_log_path: Path to falco.log
            test_ids_path: Path to test_ids.json

        Returns:
            (test_results, summary)
        """
        # Load test_ids.json
        with open(test_ids_path, 'r') as f:
            test_ids = json.load(f)

        logger.info(f"Loaded {len(test_ids)} test IDs from {test_ids_path}")

        # Parse falco.log
        detections = self.parse_falco_log(falco_log_path)

        # Pattern matching
        pattern_results = self.match_patterns(detections, test_ids)

        # Generate test-results.json format
        test_results = self.generate_test_results(pattern_results)

        # Generate summary
        total = len(pattern_results)
        detected = sum(1 for r in pattern_results if r.get('detected'))

        latencies = [r['latency_ms'] for r in pattern_results
                    if r['latency_ms'] is not None]

        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        min_latency = min(latencies) if latencies else 0
        max_latency = max(latencies) if latencies else 0

        summary = {
            'total_patterns': total,
            'detected': detected,
            'not_detected': total - detected,
            'detection_rate': detected / total if total > 0 else 0,
            'latency': {
                'avg_ms': round(avg_latency, 2),
                'min_ms': min_latency,
                'max_ms': max_latency
            }
        }

        return test_results, summary


# ========================================
# CLI Interface
# ========================================

def main():
    parser = argparse.ArgumentParser(
        description='Batch Analyzer for E2E Test Results (Public Repository)'
    )
    parser.add_argument(
        '--patterns',
        required=True,
        help='Path to patterns directory or all_patterns.json'
    )
    parser.add_argument(
        '--falco-log',
        required=True,
        help='Path to falco.log'
    )
    parser.add_argument(
        '--test-ids',
        required=True,
        help='Path to test_ids.json'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Output path for test-results.json'
    )
    parser.add_argument(
        '--summary-output',
        help='Output path for summary.json (optional)'
    )
    parser.add_argument(
        '--wait-time',
        type=int,
        default=None,
        help='Wait time in seconds (overrides BATCH_WAIT_TIME env var)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Configure logging for GitHub Actions
    log_format = '%(levelname)s: %(message)s'
    if os.environ.get('GITHUB_ACTIONS'):
        # Use GitHub Actions log commands
        log_format = '%(message)s'

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format=log_format
    )

    # Validate input files
    if not os.path.exists(args.patterns):
        logger.error(f"Patterns path not found: {args.patterns}")
        sys.exit(1)

    if not os.path.exists(args.test_ids):
        logger.error(f"Test IDs file not found: {args.test_ids}")
        sys.exit(1)

    try:
        # Run analysis
        analyzer = BatchAnalyzer(args.patterns, args.wait_time)
        test_results, summary = analyzer.analyze(args.falco_log, args.test_ids)

        # Write results
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(args.output, 'w') as f:
            json.dump(test_results, f, indent=2)

        # Write summary if requested
        if args.summary_output:
            with open(args.summary_output, 'w') as f:
                json.dump(summary, f, indent=2)

        # Print summary
        print(f"\n{'='*50}")
        print("E2E Test Analysis Complete")
        print(f"{'='*50}")
        print(f"Total patterns: {summary['total_patterns']}")
        print(f"Detected: {summary['detected']}")
        print(f"Not detected: {summary['not_detected']}")
        print(f"Detection rate: {summary['detection_rate']:.1%}")
        print(f"Avg latency: {summary['latency']['avg_ms']}ms")
        print(f"{'='*50}")
        print(f"Output: {args.output}")

        # Exit with error if detection rate is below threshold
        min_rate = float(os.environ.get('MIN_DETECTION_RATE', 0.95))
        if summary['detection_rate'] < min_rate:
            logger.warning(f"Detection rate {summary['detection_rate']:.1%} below threshold {min_rate:.1%}")
            sys.exit(1)

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON file: {e}")
        sys.exit(1)
    except IOError as e:
        logger.error(f"I/O error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
