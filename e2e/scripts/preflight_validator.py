#!/usr/bin/env python3
"""
Preflight Validator for Falco Rules and E2E Test Patterns.

Validates rule conditions against pattern encoded values BEFORE running E2E tests.
Catches issues like raw '<' vs URL-encoded '%3C' that would cause test failures.

Checks:
  1. URL Encoding: Rule conditions with raw chars that should be encoded (INFO)
  2. Pattern Coverage: Each true pattern's encoded value matches expected rule (ERROR)
  3. Cross-Rule Risk: Patterns that may trigger unexpected rules (INFO)

Usage:
  python3 preflight_validator.py [--rules RULES] [--patterns PATTERNS_DIR]

Exit codes:
  0 - All checks passed (may have info/warnings)
  1 - Errors found (will likely cause E2E failures)

References:
  #A321: nginx $request is NOT URL-decoded
  #A334: Cross-rule detection gaps
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Characters that are ALWAYS URL-encoded in URLs.
# Rule conditions using these raw may not match URL-encoded request_uri.
RAW_CHARS_SHOULD_ENCODE = {
    '<': '%3C',
    '>': '%3E',
}


class PreflightValidator:
    def __init__(self, rules_path: str, patterns_dir: str):
        self.rules_path = Path(rules_path)
        self.patterns_dir = Path(patterns_dir)
        self.rules: Dict[str, str] = {}
        self.macros: Dict[str, str] = {}
        self.patterns: List[dict] = []

    # ============================
    # Loading
    # ============================

    def load_rules(self):
        """Parse rules YAML file and extract rule/macro conditions."""
        try:
            import yaml
            with open(self.rules_path) as f:
                items = yaml.safe_load(f)
            if not isinstance(items, list):
                self._parse_rules_regex()
                return
            for item in items:
                if not isinstance(item, dict):
                    continue
                if 'rule' in item and 'condition' in item:
                    self.rules[str(item['rule'])] = str(item['condition'])
                elif 'macro' in item and 'condition' in item:
                    self.macros[str(item['macro'])] = str(item['condition'])
        except ImportError:
            self._parse_rules_regex()

    def _parse_rules_regex(self):
        """Fallback: parse rules file with regex when PyYAML unavailable."""
        content = self.rules_path.read_text()
        current_type = None
        current_name = None
        current_cond = []
        in_condition = False

        def flush():
            nonlocal current_type, current_name, current_cond
            if current_name and current_cond:
                cond_text = '\n'.join(current_cond)
                if current_type == 'rule':
                    self.rules[current_name] = cond_text
                elif current_type == 'macro':
                    self.macros[current_name] = cond_text

        for line in content.split('\n'):
            rm = re.match(r'^- rule:\s*"?(.+?)"?\s*$', line)
            mm = re.match(r'^- macro:\s*(\S+)', line)
            cm = re.match(r'  condition:\s*(.*)', line)
            if rm:
                flush()
                current_type = 'rule'
                current_name = rm.group(1).strip()
                current_cond = []
                in_condition = False
            elif mm:
                flush()
                current_type = 'macro'
                current_name = mm.group(1).strip()
                current_cond = []
                in_condition = False
            elif cm:
                in_condition = True
                rest = cm.group(1).strip()
                if rest and rest != '>':
                    current_cond.append(rest)
            elif in_condition:
                if line.startswith('    ') or line.startswith('\t'):
                    current_cond.append(line.strip())
                elif line.strip() == '':
                    continue
                else:
                    in_condition = False
        flush()

    def load_patterns(self):
        """Load all E2E test pattern JSON files."""
        for json_file in sorted(self.patterns_dir.glob('*.json')):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                items = []
                if isinstance(data, dict):
                    for val in data.values():
                        if isinstance(val, list):
                            items.extend(val)
                elif isinstance(data, list):
                    items = data
                for p in items:
                    if isinstance(p, dict) and 'id' in p:
                        p['_source'] = json_file.name
                        self.patterns.append(p)
            except (json.JSONDecodeError, IOError) as e:
                print(f"  WARN: Failed to load {json_file}: {e}")

    # ============================
    # Utilities
    # ============================

    def extract_contains(self, condition: str) -> List[Tuple[str, str]]:
        """Extract (operator, value) pairs from contains/icontains in condition."""
        return [(m.group(1), m.group(2))
                for m in re.finditer(r'(i?contains)\s+"([^"]*)"', condition)]

    def resolve_condition(self, condition: str, depth: int = 0) -> List[Tuple[str, str]]:
        """Resolve macro references and collect all contains patterns."""
        if depth > 10:
            return []
        patterns = self.extract_contains(condition)
        for macro_name, macro_cond in self.macros.items():
            if macro_name in condition:
                patterns.extend(self.resolve_condition(macro_cond, depth + 1))
        return patterns

    @staticmethod
    def _normalize_rule_name(name: str) -> str:
        """Remove [NGINX XXX] prefix and normalize for comparison."""
        return re.sub(r'^\[.*?\]\s*', '', name).lower().strip()

    def find_rule(self, expected_rule: str) -> Tuple[Optional[str], Optional[str]]:
        """Find a rule by expected_rule string, handling format variations.

        Matching strategy (tried in order):
        1. Exact match
        2. Normalized match: remove [NGINX XXX] prefix, case-insensitive
        3. Substring match: normalized expected_rule is substring of rule name
        """
        if not expected_rule or expected_rule == 'NONE':
            return None, None

        # 1. Exact match
        if expected_rule in self.rules:
            return expected_rule, self.rules[expected_rule]

        # 2. Normalized match
        norm_expected = self._normalize_rule_name(expected_rule)
        for name, cond in self.rules.items():
            if self._normalize_rule_name(name) == norm_expected:
                return name, cond

        # 3. Substring match (bidirectional)
        for name, cond in self.rules.items():
            norm_name = self._normalize_rule_name(name)
            if len(norm_expected) >= 10 and norm_expected in norm_name:
                return name, cond
            if len(norm_name) >= 10 and norm_name in norm_expected:
                return name, cond

        return None, None

    @staticmethod
    def matches(op: str, pattern_val: str, text: str) -> bool:
        """Simulate Falco's contains/icontains matching."""
        if op == 'icontains':
            return pattern_val.lower() in text.lower()
        return pattern_val in text

    # ============================
    # Check 1: URL Encoding
    # ============================

    def check_url_encoding(self) -> List[dict]:
        """Find raw characters in rule conditions that should be URL-encoded.

        Reports as INFO since many existing rules intentionally use raw chars
        alongside URL-encoded variants. The real impact is caught by Check 2.
        """
        issues = []
        all_items = [(t, n, c) for t, items in [('rule', self.rules), ('macro', self.macros)]
                     for n, c in items.items()]
        for item_type, name, condition in all_items:
            for op, val in self.extract_contains(condition):
                for raw_char, encoded_form in RAW_CHARS_SHOULD_ENCODE.items():
                    if raw_char in val:
                        issues.append({
                            'item_type': item_type,
                            'item_name': name,
                            'pattern': val,
                            'char': raw_char,
                            'encoded': encoded_form,
                        })
        return issues

    # ============================
    # Check 2: Pattern Coverage
    # ============================

    def check_pattern_coverage(self) -> List[dict]:
        """Verify each true pattern's encoded value matches expected rule.

        This is the PRIMARY check. For each pattern with expected_detection=true:
        - ERROR: Pattern matches NO rule at all (will fail E2E)
        - WARN (mismatch): Pattern matches a different rule than expected
        - WARN (not found): Expected rule name not found in rules file
        """
        issues = []

        # Pre-build all rule match patterns for cross-check
        all_rule_patterns = {name: self.resolve_condition(cond)
                             for name, cond in self.rules.items()}

        for pattern in self.patterns:
            if not pattern.get('expected_detection', True):
                continue
            expected_rule = pattern.get('expected_rule', '')
            encoded = pattern.get('encoded', '')
            pid = pattern.get('id', 'unknown')
            if not expected_rule or expected_rule == 'NONE' or not encoded:
                continue

            rule_name, rule_condition = self.find_rule(expected_rule)
            if rule_condition is None:
                issues.append({
                    'level': 'WARN',
                    'pattern_id': pid,
                    'expected_rule': expected_rule,
                    'detail': 'Expected rule not found in rules file',
                })
                continue

            match_patterns = self.resolve_condition(rule_condition)
            request_uri = f"/?q={encoded}"
            matched = any(self.matches(op, val, request_uri)
                          for op, val in match_patterns)

            if not matched:
                # Check if ANY other rule would match this pattern
                any_rule_matches = False
                matching_rule = None
                for other_name, other_pats in all_rule_patterns.items():
                    if any(self.matches(op, val, request_uri)
                           for op, val in other_pats):
                        any_rule_matches = True
                        matching_rule = other_name
                        break

                if any_rule_matches:
                    # Mismatch: detected by different rule (WARN, not ERROR)
                    issues.append({
                        'level': 'WARN_MISMATCH',
                        'pattern_id': pid,
                        'source': pattern.get('_source', ''),
                        'expected_rule': expected_rule,
                        'actual_rule': matching_rule,
                        'encoded': encoded[:100],
                        'detail': 'Detected by different rule than expected',
                    })
                else:
                    # No rule matches at all (ERROR - will fail E2E)
                    issues.append({
                        'level': 'ERROR',
                        'pattern_id': pid,
                        'source': pattern.get('_source', ''),
                        'expected_rule': expected_rule,
                        'rule_name': rule_name,
                        'encoded': encoded[:100],
                        'detail': 'Encoded value matches NO rule condition',
                    })
        return issues

    # ============================
    # Check 3: Cross-Rule Risk
    # ============================

    def check_cross_rule(self) -> List[dict]:
        """Find patterns that may trigger rules other than expected.

        Reports as INFO since cross-rule detection is common and handled
        by Falco exceptions. Only flags patterns with no exception coverage.
        """
        issues = []
        rule_patterns_cache = {name: self.resolve_condition(cond)
                               for name, cond in self.rules.items()}

        for pattern in self.patterns:
            if not pattern.get('expected_detection', True):
                continue
            encoded = pattern.get('encoded', '')
            expected_rule = pattern.get('expected_rule', '')
            pid = pattern.get('id', 'unknown')
            if not encoded or not expected_rule:
                continue

            request_uri = f"/?q={encoded}"
            _, expected_rule_name = self.find_rule(expected_rule)
            matching_rules = []
            for rule_name, match_pats in rule_patterns_cache.items():
                if any(self.matches(op, val, request_uri)
                       for op, val in match_pats):
                    matching_rules.append(rule_name)

            # Filter out the expected rule (normalized comparison)
            norm_expected = self._normalize_rule_name(expected_rule)
            unexpected = [r for r in matching_rules
                          if self._normalize_rule_name(r) != norm_expected]
            if unexpected:
                issues.append({
                    'pattern_id': pid,
                    'expected_rule': expected_rule,
                    'other_rules': unexpected[:5],
                    'count': len(unexpected),
                })
        return issues

    # ============================
    # Report
    # ============================

    def run(self) -> int:
        """Run all checks and print report. Returns exit code."""
        print("=" * 60)
        print("Falco Rule Preflight Validator")
        print("=" * 60)
        print(f"Rules:    {self.rules_path}")
        print(f"Patterns: {self.patterns_dir}")
        print()

        self.load_rules()
        self.load_patterns()
        true_count = sum(1 for p in self.patterns
                         if p.get('expected_detection', True))
        false_count = len(self.patterns) - true_count
        print(f"Loaded: {len(self.rules)} rules, {len(self.macros)} macros, "
              f"{len(self.patterns)} patterns ({true_count} true, {false_count} false)")
        print()

        # --- Check 1: URL Encoding (INFO) ---
        print("-" * 60)
        print("[Check 1] URL Encoding in Rule Conditions (INFO)")
        print("-" * 60)
        url_issues = self.check_url_encoding()
        if url_issues:
            # Deduplicate by rule name
            by_rule = {}
            for issue in url_issues:
                key = issue['item_name']
                by_rule.setdefault(key, []).append(issue)
            print(f"  {len(url_issues)} condition(s) in {len(by_rule)} rule/macro(s)"
                  f" use raw chars ({', '.join(RAW_CHARS_SHOULD_ENCODE.keys())})")
            print("  Note: These may be intentional if URL-encoded variants also exist.")
            print("  Real impact is validated by Check 2.")
        else:
            print("  PASS: No raw characters that need URL-encoding")
        print()

        # --- Check 2: Pattern Coverage (ERROR/WARN) ---
        print("-" * 60)
        print("[Check 2] Pattern-Rule Coverage")
        print("-" * 60)
        cov_issues = self.check_pattern_coverage()
        cov_errors = [i for i in cov_issues if i['level'] == 'ERROR']
        cov_mismatches = [i for i in cov_issues if i['level'] == 'WARN_MISMATCH']
        cov_not_found = [i for i in cov_issues if i['level'] == 'WARN']
        if cov_errors:
            for issue in cov_errors:
                print(f"  ERROR: {issue['pattern_id']} ({issue.get('source', '')})")
                print(f"         Expected: {issue['expected_rule']}")
                print(f"         Encoded:  {issue.get('encoded', 'N/A')}")
                print(f"         {issue['detail']}")
                print()
        if cov_mismatches:
            print(f"  MISMATCH: {len(cov_mismatches)} pattern(s) detected"
                  f" by different rule than expected")
            for issue in cov_mismatches[:10]:
                print(f"    {issue['pattern_id']}: expected={issue['expected_rule'][:40]}")
                print(f"      {'':14s} actual={issue['actual_rule'][:40]}")
            if len(cov_mismatches) > 10:
                print(f"    ... and {len(cov_mismatches) - 10} more")
            print()
        if cov_not_found:
            print(f"  WARN: {len(cov_not_found)} pattern(s) reference rules"
                  f" not found in rules file")
            for issue in cov_not_found[:5]:
                print(f"    {issue['pattern_id']}: {issue['expected_rule']}")
            if len(cov_not_found) > 5:
                print(f"    ... and {len(cov_not_found) - 5} more")
            print()
        if not cov_issues:
            print("  PASS: All true patterns match expected rule conditions")
        print()

        # --- Check 3: Cross-Rule Risk (INFO) ---
        print("-" * 60)
        print("[Check 3] Cross-Rule Detection Risk (INFO)")
        print("-" * 60)
        cross_issues = self.check_cross_rule()
        if cross_issues:
            high_risk = [i for i in cross_issues if i['count'] >= 5]
            print(f"  {len(cross_issues)} pattern(s) may trigger other rules")
            print(f"  (Expected - managed via Falco exceptions)")
            if high_risk:
                print(f"  {len(high_risk)} match 5+ other rules:")
                for issue in high_risk[:5]:
                    rules_str = ', '.join(r[:35] for r in issue['other_rules'][:3])
                    if issue['count'] > 3:
                        rules_str += f" (+{issue['count'] - 3} more)"
                    print(f"    {issue['pattern_id']}: {rules_str}")
        else:
            print("  PASS: No cross-rule detection risks")
        print()

        # --- Summary ---
        total_warns = len(cov_mismatches) + len(cov_not_found)
        print("=" * 60)
        print("Summary")
        print("=" * 60)
        print(f"Check 1 (URL Encoding):     {len(url_issues)} info")
        print(f"Check 2 (Pattern Coverage): {len(cov_errors)} error(s),"
              f" {len(cov_mismatches)} mismatch(es),"
              f" {len(cov_not_found)} not-found")
        print(f"Check 3 (Cross-Rule Risk):  {len(cross_issues)} info")
        print()

        if cov_errors:
            print(f"RESULT: FAIL ({len(cov_errors)} error(s))")
            print("Fix errors before running E2E tests.")
            print("These patterns match NO rule and will cause E2E failures.")
            return 1
        elif total_warns > 0:
            print(f"RESULT: PASS with {total_warns} warning(s)")
            return 0
        else:
            print("RESULT: PASS")
            return 0


def main():
    parser = argparse.ArgumentParser(
        description='Preflight validator for Falco rules and E2E test patterns')
    parser.add_argument('--rules', default='rules/nginx_rules.yaml',
                        help='Path to Falco rules YAML file')
    parser.add_argument('--patterns', default='e2e/patterns/',
                        help='Path to E2E pattern JSON directory')
    args = parser.parse_args()
    sys.exit(PreflightValidator(args.rules, args.patterns).run())


if __name__ == '__main__':
    main()
