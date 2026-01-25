#!/usr/bin/env python3
"""
Generate Rule Mapping Trend HTML Page for E2E Reports

Issue #68: Add Rule Mapping Trend graph separate from Allure Categories

This script generates an HTML page with an interactive Rule Mapping Trend chart
using Chart.js. The chart shows trends for:
- Rule Match (green)
- Rule Mismatch (red)
- Expected Not Detected (blue)
- Not Defined (gray)

Usage:
    python generate_rule_mapping_trend_html.py \
        --test-results results/test-results.json \
        --run-number 100 \
        --report-url "https://example.com/e2e-report/100/" \
        --history-input rule-mapping-trend-history.json \
        --history-output rule-mapping-trend-history.json \
        --html-output rule-mapping-trend.html \
        --max-history 20
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Rule Mapping status categories
CATEGORY_MATCH = "Rule Match"
CATEGORY_MISMATCH = "Rule Mismatch"
CATEGORY_EXPECTED_NOT_DETECTED = "Expected Not Detected"
CATEGORY_NOT_DEFINED = "Not Defined"


def calculate_rule_mapping_status(test_result: Dict) -> str:
    """Calculate Rule Mapping status for a single test result."""
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
    """Calculate Rule Mapping statistics from test results."""
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
    stats: Dict[str, int],
    timestamp: str = None
) -> Dict:
    """Create a single trend entry."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "buildOrder": run_number,
        "reportName": f"#{run_number}",
        "reportUrl": report_url,
        "timestamp": timestamp,
        "data": stats
    }


def merge_trend_history(
    new_entry: Dict,
    existing_history: List[Dict],
    max_history: int = 20
) -> List[Dict]:
    """Merge new trend entry into existing history."""
    updated = [new_entry] + existing_history

    # Remove duplicates (same buildOrder)
    seen = set()
    deduplicated = []
    for entry in updated:
        build_order = entry.get('buildOrder')
        if build_order not in seen:
            seen.add(build_order)
            deduplicated.append(entry)

    # Sort by buildOrder ascending (oldest first for chart display)
    deduplicated.sort(key=lambda x: x.get('buildOrder', 0))

    # Keep only the last N entries
    return deduplicated[-max_history:]


def generate_html(history: List[Dict], current_run: int) -> str:
    """Generate HTML page with Chart.js trend chart."""

    # Prepare data for Chart.js
    labels = [entry.get('reportName', f"#{entry.get('buildOrder', '?')}") for entry in history]
    urls = [entry.get('reportUrl', '#') for entry in history]

    match_data = [entry.get('data', {}).get(CATEGORY_MATCH, 0) for entry in history]
    mismatch_data = [entry.get('data', {}).get(CATEGORY_MISMATCH, 0) for entry in history]
    expected_not_detected_data = [entry.get('data', {}).get(CATEGORY_EXPECTED_NOT_DETECTED, 0) for entry in history]
    not_defined_data = [entry.get('data', {}).get(CATEGORY_NOT_DEFINED, 0) for entry in history]

    # Calculate current statistics
    current_entry = next((e for e in history if e.get('buildOrder') == current_run), None)
    if current_entry:
        current_stats = current_entry.get('data', {})
        total = sum(current_stats.values())
        match_count = current_stats.get(CATEGORY_MATCH, 0)
        mismatch_count = current_stats.get(CATEGORY_MISMATCH, 0)
        match_rate = (match_count / total * 100) if total > 0 else 0
    else:
        total = 0
        match_count = 0
        mismatch_count = 0
        match_rate = 0

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rule Mapping Trend - E2E Tests #{current_run}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
            color: #e0e0e0;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        h1 {{
            font-size: 2rem;
            color: #4CAF50;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #888;
            font-size: 1rem;
        }}
        .back-link {{
            display: inline-block;
            margin-top: 10px;
            color: #64b5f6;
            text-decoration: none;
        }}
        .back-link:hover {{
            text-decoration: underline;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .stat-card.match {{
            border-color: rgba(76, 175, 80, 0.5);
        }}
        .stat-card.mismatch {{
            border-color: rgba(244, 67, 54, 0.5);
        }}
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-value.green {{ color: #4CAF50; }}
        .stat-value.red {{ color: #f44336; }}
        .stat-value.blue {{ color: #2196F3; }}
        .stat-value.gray {{ color: #9e9e9e; }}
        .stat-label {{
            color: #888;
            font-size: 0.9rem;
        }}
        .chart-container {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .chart-title {{
            font-size: 1.2rem;
            color: #fff;
            margin-bottom: 15px;
            text-align: center;
        }}
        .chart-wrapper {{
            position: relative;
            height: 400px;
        }}
        .legend-info {{
            text-align: center;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 0.85rem;
            color: #888;
        }}
        .legend-item {{
            display: inline-block;
            margin: 0 15px;
        }}
        .legend-color {{
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 2px;
            margin-right: 5px;
            vertical-align: middle;
        }}
        footer {{
            text-align: center;
            color: #666;
            font-size: 0.8rem;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Rule Mapping Trend</h1>
            <p class="subtitle">E2E Tests #{current_run} - Pattern Rule Verification</p>
            <a href="../{current_run}/" class="back-link">&larr; Back to Allure Report</a>
        </header>

        <div class="stats-grid">
            <div class="stat-card match">
                <div class="stat-value green">{match_count}</div>
                <div class="stat-label">Rule Match</div>
            </div>
            <div class="stat-card mismatch">
                <div class="stat-value red">{mismatch_count}</div>
                <div class="stat-label">Rule Mismatch</div>
            </div>
            <div class="stat-card">
                <div class="stat-value blue">{current_stats.get(CATEGORY_EXPECTED_NOT_DETECTED, 0) if current_entry else 0}</div>
                <div class="stat-label">Expected Not Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value gray">{match_rate:.1f}%</div>
                <div class="stat-label">Match Rate</div>
            </div>
        </div>

        <div class="chart-container">
            <h2 class="chart-title">Rule Mapping Trend (Last {len(history)} Runs)</h2>
            <div class="chart-wrapper">
                <canvas id="trendChart"></canvas>
            </div>
            <div class="legend-info">
                <span class="legend-item"><span class="legend-color" style="background: #4CAF50;"></span>Rule Match</span>
                <span class="legend-item"><span class="legend-color" style="background: #f44336;"></span>Rule Mismatch</span>
                <span class="legend-item"><span class="legend-color" style="background: #2196F3;"></span>Expected Not Detected</span>
                <span class="legend-item"><span class="legend-color" style="background: #9e9e9e;"></span>Not Defined</span>
            </div>
        </div>

        <footer>
            Generated at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} |
            <a href="https://github.com/takaosgb3/falco-plugin-nginx" style="color: #64b5f6;">falco-plugin-nginx</a>
        </footer>
    </div>

    <script>
        const ctx = document.getElementById('trendChart').getContext('2d');
        const labels = {json.dumps(labels)};
        const urls = {json.dumps(urls)};

        const chart = new Chart(ctx, {{
            type: 'line',
            data: {{
                labels: labels,
                datasets: [
                    {{
                        label: 'Rule Match',
                        data: {json.dumps(match_data)},
                        borderColor: '#4CAF50',
                        backgroundColor: 'rgba(76, 175, 80, 0.1)',
                        fill: true,
                        tension: 0.3,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }},
                    {{
                        label: 'Rule Mismatch',
                        data: {json.dumps(mismatch_data)},
                        borderColor: '#f44336',
                        backgroundColor: 'rgba(244, 67, 54, 0.1)',
                        fill: true,
                        tension: 0.3,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }},
                    {{
                        label: 'Expected Not Detected',
                        data: {json.dumps(expected_not_detected_data)},
                        borderColor: '#2196F3',
                        backgroundColor: 'rgba(33, 150, 243, 0.1)',
                        fill: true,
                        tension: 0.3,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }},
                    {{
                        label: 'Not Defined',
                        data: {json.dumps(not_defined_data)},
                        borderColor: '#9e9e9e',
                        backgroundColor: 'rgba(158, 158, 158, 0.1)',
                        fill: true,
                        tension: 0.3,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                interaction: {{
                    mode: 'index',
                    intersect: false
                }},
                plugins: {{
                    legend: {{
                        display: false
                    }},
                    tooltip: {{
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#fff',
                        bodyColor: '#e0e0e0',
                        padding: 12,
                        displayColors: true,
                        callbacks: {{
                            title: function(context) {{
                                const idx = context[0].dataIndex;
                                return 'Run ' + labels[idx];
                            }},
                            afterBody: function(context) {{
                                const idx = context[0].dataIndex;
                                const total = {json.dumps(match_data)}[idx] + {json.dumps(mismatch_data)}[idx] +
                                             {json.dumps(expected_not_detected_data)}[idx] + {json.dumps(not_defined_data)}[idx];
                                const matchRate = total > 0 ? ({json.dumps(match_data)}[idx] / total * 100).toFixed(1) : 0;
                                return '\\nMatch Rate: ' + matchRate + '%\\nTotal: ' + total;
                            }}
                        }}
                    }}
                }},
                scales: {{
                    x: {{
                        grid: {{
                            color: 'rgba(255, 255, 255, 0.1)'
                        }},
                        ticks: {{
                            color: '#888'
                        }}
                    }},
                    y: {{
                        beginAtZero: true,
                        grid: {{
                            color: 'rgba(255, 255, 255, 0.1)'
                        }},
                        ticks: {{
                            color: '#888'
                        }}
                    }}
                }},
                onClick: function(evt, elements) {{
                    if (elements.length > 0) {{
                        const idx = elements[0].index;
                        if (urls[idx]) {{
                            window.open(urls[idx], '_blank');
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""

    return html


def main():
    parser = argparse.ArgumentParser(
        description='Generate Rule Mapping Trend HTML Page (Issue #68)'
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
        help='Path to existing history JSON (optional)'
    )
    parser.add_argument(
        '--history-output',
        required=True,
        help='Output path for updated history JSON'
    )
    parser.add_argument(
        '--html-output',
        required=True,
        help='Output path for HTML trend page'
    )
    parser.add_argument(
        '--max-history',
        type=int,
        default=20,
        help='Maximum number of history entries to keep (default: 20)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

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

    # Write history JSON
    history_output_path = Path(args.history_output)
    history_output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(history_output_path, 'w') as f:
        json.dump(updated_history, f, indent=2)
    logger.info(f"Written {len(updated_history)} history entries to {args.history_output}")

    # Generate HTML
    html_content = generate_html(updated_history, args.run_number)

    html_output_path = Path(args.html_output)
    html_output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(html_output_path, 'w') as f:
        f.write(html_content)
    logger.info(f"Generated HTML trend page: {args.html_output}")

    # Print summary
    total = sum(stats.values())
    match_rate = (stats[CATEGORY_MATCH] / total * 100) if total > 0 else 0

    print(f"\n{'='*50}")
    print("Rule Mapping Trend HTML Generated (Issue #68)")
    print(f"{'='*50}")
    print(f"Run Number: {args.run_number}")
    print(f"Total Patterns: {total}")
    print(f"  - {CATEGORY_MATCH}: {stats[CATEGORY_MATCH]}")
    print(f"  - {CATEGORY_MISMATCH}: {stats[CATEGORY_MISMATCH]}")
    print(f"  - {CATEGORY_EXPECTED_NOT_DETECTED}: {stats[CATEGORY_EXPECTED_NOT_DETECTED]}")
    print(f"  - {CATEGORY_NOT_DEFINED}: {stats[CATEGORY_NOT_DEFINED]}")
    print(f"Match Rate: {match_rate:.1f}%")
    print(f"HTML Output: {args.html_output}")
    print(f"{'='*50}")


if __name__ == '__main__':
    main()
