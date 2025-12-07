"""
pytest configuration for E2E Allure Report wrapper

Issue #3: E2E test workflow for falco-plugin-nginx (Public Repository)
Based on: terraform/k6-e2e/allure-poc/conftest.py (PRIVATE repo)
"""

import pytest

# Default paths for GitHub Actions environment
DEFAULT_RULES_DIR = "/etc/falco/rules.d"


def pytest_addoption(parser):
    """Add custom pytest command line options"""
    parser.addoption(
        "--test-results",
        action="store",
        default=None,
        help="Path to E2E test results JSON file"
    )
    parser.addoption(
        "--logs-dir",
        action="store",
        default=None,
        help="Path to log files directory"
    )
    parser.addoption(
        "--rules-dir",
        action="store",
        default=DEFAULT_RULES_DIR,
        help=f"Path to Falco rules directory (default: {DEFAULT_RULES_DIR})"
    )


def pytest_configure(config):
    """Configure pytest with custom options"""
    test_results_path = config.getoption("--test-results")
    logs_dir_path = config.getoption("--logs-dir")
    rules_dir_path = config.getoption("--rules-dir")

    # Store in config for access from tests
    if test_results_path:
        config.test_results = test_results_path
    if logs_dir_path:
        config.logs_dir = logs_dir_path
    if rules_dir_path:
        config.rules_dir = rules_dir_path

    # Pre-warm caches for fair test duration measurement
    _prewarm_caches()


def _prewarm_caches():
    """
    Pre-warm all caches before tests run.

    This ensures that the first test case doesn't bear the initialization
    overhead, making Duration measurements fair across all test cases.
    """
    try:
        from test_e2e_wrapper import load_all_patterns
        patterns = load_all_patterns()
        print(f"Pre-warmed pattern cache: {len(patterns)} patterns loaded")
    except Exception as e:
        print(f"Warning: Failed to pre-warm pattern cache: {e}")
