/**
 * k6 E2E Main Test Script for Public Repository
 *
 * Issue #3: E2E test workflow for falco-plugin-nginx
 * Based on: terraform/k6-e2e/scripts/main.js (PRIVATE repo)
 *
 * Modifications for GitHub Actions environment:
 * - TARGET_IP: localhost (default)
 * - TARGET_PORT: 80 (single port, vs 8001-8005 in AWS)
 * - Detection API polling removed (batch processing mode)
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { SharedArray } from 'k6/data';
import { Counter, Trend, Rate } from 'k6/metrics';
import { scenario } from 'k6/execution';

// ========================================
// Environment Variables
// ========================================
const TARGET_IP = __ENV.TARGET_IP || 'localhost';
const TARGET_PORT = __ENV.TARGET_PORT || '80';

// ========================================
// Global array for test_id tracking (FR-001)
// ========================================
let testIdRecords = [];

// ========================================
// Custom Metrics
// ========================================
const attacksSent = new Counter('attacks_sent');

// Category-specific metrics
const sqliAttacks = new Counter('sqli_attacks');
const xssAttacks = new Counter('xss_attacks');
const pathAttacks = new Counter('path_attacks');
const cmdinjAttacks = new Counter('cmdinj_attacks');
const otherAttacks = new Counter('other_attacks');

// ========================================
// Load attack patterns (SharedArray for efficiency)
// ========================================
const sqliPatterns = new SharedArray('sqli', function() {
    const data = JSON.parse(open('../patterns/sqli_patterns.json'));
    return data.patterns;
});

const xssPatterns = new SharedArray('xss', function() {
    const data = JSON.parse(open('../patterns/xss_patterns.json'));
    return data.patterns;
});

const pathPatterns = new SharedArray('path', function() {
    const data = JSON.parse(open('../patterns/path_patterns.json'));
    return data.patterns;
});

const cmdinjPatterns = new SharedArray('cmdinj', function() {
    const data = JSON.parse(open('../patterns/cmdinj_patterns.json'));
    return data.patterns;
});

const otherPatterns = new SharedArray('other', function() {
    const data = JSON.parse(open('../patterns/other_patterns.json'));
    return data.patterns;
});

// ========================================
// Test Options
// ========================================
export const options = {
    scenarios: {
        sqli_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: sqliPatterns.length,
            exec: 'testSQLi',
            startTime: '0s',
            tags: { category: 'sqli' }
        },
        xss_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: xssPatterns.length,
            exec: 'testXSS',
            startTime: '5s',
            tags: { category: 'xss' }
        },
        path_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: pathPatterns.length,
            exec: 'testPath',
            startTime: '10s',
            tags: { category: 'path' }
        },
        cmdinj_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: cmdinjPatterns.length,
            exec: 'testCmdInj',
            startTime: '15s',
            tags: { category: 'cmdinj' }
        },
        other_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: otherPatterns.length,
            exec: 'testOther',
            startTime: '20s',
            tags: { category: 'other' }
        }
    },
    thresholds: {
        'http_req_duration': ['p(95)<5000'],  // 95% of requests under 5s
        'http_req_failed': ['rate<0.05'],      // Less than 5% failure rate
        'attacks_sent': ['count==65']          // All 65 patterns sent
    },
    summaryTimeUnit: 'ms',
    summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max', 'count']
};

// ========================================
// Common Attack Execution Function
// ========================================
function executeAttack(pattern, categoryMetric) {
    const port = parseInt(TARGET_PORT);
    const sentAt = Date.now();
    const testId = `${pattern.id}-${sentAt}-${Math.random().toString(36).substring(7)}`;
    const url = `http://${TARGET_IP}:${port}/`;

    // Send attack request with test tracking headers
    const res = http.get(`${url}?q=${pattern.encoded}`, {
        headers: {
            'X-Test-ID': testId,
            'X-Category': pattern.category.toUpperCase(),
            'X-Pattern-ID': pattern.id
        },
        tags: {
            pattern_id: pattern.id,
            category: pattern.category,
            subcategory: pattern.subcategory
        }
    });

    // Response validation
    const nginxOK = check(res, {
        'nginx responded': (r) => r.status === 200 || r.status === 400
    }, { category: pattern.category });

    // Record metrics
    attacksSent.add(1, { category: pattern.category });
    categoryMetric.add(1);

    // Record test_id for batch analysis (FR-001)
    testIdRecords.push({
        test_id: testId,
        pattern_id: pattern.id,
        category: pattern.category,
        sent_at: sentAt
    });

    console.log(`[SENT] ${pattern.id}: test_id=${testId}`);

    sleep(0.5);  // Rate limiting (DD-005: 500ms interval)
}

// ========================================
// Category Test Functions
// ========================================
export function testSQLi() {
    group('SQL Injection Tests', function() {
        const pattern = sqliPatterns[scenario.iterationInTest];
        executeAttack(pattern, sqliAttacks);
    });
}

export function testXSS() {
    group('XSS Tests', function() {
        const pattern = xssPatterns[scenario.iterationInTest];
        executeAttack(pattern, xssAttacks);
    });
}

export function testPath() {
    group('Path Traversal Tests', function() {
        const pattern = pathPatterns[scenario.iterationInTest];
        executeAttack(pattern, pathAttacks);
    });
}

export function testCmdInj() {
    group('Command Injection Tests', function() {
        const pattern = cmdinjPatterns[scenario.iterationInTest];
        executeAttack(pattern, cmdinjAttacks);
    });
}

export function testOther() {
    group('Other Threats Tests', function() {
        const pattern = otherPatterns[scenario.iterationInTest];
        executeAttack(pattern, otherAttacks);
    });
}

// ========================================
// Setup/Teardown
// ========================================
export function setup() {
    console.log('========================================');
    console.log('k6 E2E Test Starting (Public Repo Mode)');
    console.log(`Target: ${TARGET_IP}:${TARGET_PORT}`);
    console.log('Total Patterns: 65');
    console.log('  - SQLi: 19');
    console.log('  - XSS: 11');
    console.log('  - Path: 20');
    console.log('  - CmdInj: 10');
    console.log('  - Other: 5');
    console.log('========================================');
}

export function teardown(data) {
    console.log('========================================');
    console.log('Test Complete - Batch analysis will follow');
    console.log(`Total attacks sent: ${testIdRecords.length}`);
    console.log('========================================');
}

// ========================================
// Summary Handler (outputs test_ids.json for batch analysis)
// ========================================
export function handleSummary(data) {
    const completeSummary = {
        metrics: data.metrics,
        root_group: data.root_group,
        test_results: {
            total_attacks: data.metrics.attacks_sent ? data.metrics.attacks_sent.values.count : 0,
            categories: {
                sqli: data.metrics.sqli_attacks ? data.metrics.sqli_attacks.values.count : 0,
                xss: data.metrics.xss_attacks ? data.metrics.xss_attacks.values.count : 0,
                path: data.metrics.path_attacks ? data.metrics.path_attacks.values.count : 0,
                cmdinj: data.metrics.cmdinj_attacks ? data.metrics.cmdinj_attacks.values.count : 0,
                other: data.metrics.other_attacks ? data.metrics.other_attacks.values.count : 0
            }
        }
    };

    const customSummaryForStdout = {
        test_results: completeSummary.test_results,
        test_ids_count: testIdRecords.length
    };

    return {
        'stdout': JSON.stringify(customSummaryForStdout, null, 2),
        '../results/summary.json': JSON.stringify(completeSummary, null, 2),
        '../results/test_ids.json': JSON.stringify(testIdRecords, null, 2)
    };
}
