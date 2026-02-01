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
// Phase 2: New category metrics (Issue #780)
const ldapAttacks = new Counter('ldap_attacks');
const xxeAttacks = new Counter('xxe_attacks');
const graphqlAttacks = new Counter('graphql_attacks');
// Phase 3: New category metrics (Issue #783)
const xpathAttacks = new Counter('xpath_attacks');
const sstiAttacks = new Counter('ssti_attacks');
const nosqlExtendedAttacks = new Counter('nosql_extended_attacks');
// Phase 5: Pickle Deserialization metrics (Issue #64)
const pickleAttacks = new Counter('pickle_attacks');
// Phase 7: Prototype Pollution and HTTP Smuggling metrics
const prototypePollutionAttacks = new Counter('prototype_pollution_attacks');
const httpSmugglingAttacks = new Counter('http_smuggling_attacks');

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

// Phase 2: New category patterns (Issue #780)
const ldapPatterns = new SharedArray('ldap', function() {
    const data = JSON.parse(open('../patterns/ldap_patterns.json'));
    return data.patterns;
});

const xxePatterns = new SharedArray('xxe', function() {
    const data = JSON.parse(open('../patterns/xxe_patterns.json'));
    return data.patterns;
});

const graphqlPatterns = new SharedArray('graphql', function() {
    const data = JSON.parse(open('../patterns/graphql_patterns.json'));
    return data.patterns;
});

// Phase 3: New category patterns (Issue #783)
const xpathPatterns = new SharedArray('xpath', function() {
    const data = JSON.parse(open('../patterns/xpath_patterns.json'));
    return data.patterns;
});

const sstiPatterns = new SharedArray('ssti', function() {
    const data = JSON.parse(open('../patterns/ssti_patterns.json'));
    return data.patterns;
});

const nosqlExtendedPatterns = new SharedArray('nosql_extended', function() {
    const data = JSON.parse(open('../patterns/nosql_extended_patterns.json'));
    return data.patterns;
});

const apiSecurityPatterns = new SharedArray('api_security', function() {
    const data = JSON.parse(open('../patterns/api_security_patterns.json'));
    return data.patterns;
});

// Phase 5: Pickle Deserialization patterns (Issue #64)
const picklePatterns = new SharedArray('pickle', function() {
    const data = JSON.parse(open('../patterns/pickle_patterns.json'));
    return data.patterns;
});

// Phase 7: Prototype Pollution patterns
const prototypePollutionPatterns = new SharedArray('prototype_pollution', function() {
    const data = JSON.parse(open('../patterns/prototype_pollution_patterns.json'));
    return data.patterns;
});

// Phase 7: HTTP Smuggling patterns
const httpSmugglingPatterns = new SharedArray('http_smuggling', function() {
    const data = JSON.parse(open('../patterns/http_smuggling_patterns.json'));
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
        },
        // Phase 2: New category scenarios (Issue #780)
        ldap_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: ldapPatterns.length,
            exec: 'testLDAP',
            startTime: '25s',
            tags: { category: 'ldap' }
        },
        xxe_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: xxePatterns.length,
            exec: 'testXXE',
            startTime: '30s',
            tags: { category: 'xxe' }
        },
        graphql_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: graphqlPatterns.length,
            exec: 'testGraphQL',
            startTime: '35s',
            tags: { category: 'graphql' }
        },
        // Phase 3: New category scenarios (Issue #783)
        xpath_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: xpathPatterns.length,
            exec: 'testXPath',
            startTime: '40s',
            tags: { category: 'xpath' }
        },
        ssti_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: sstiPatterns.length,
            exec: 'testSSTI',
            startTime: '45s',
            tags: { category: 'ssti' }
        },
        nosql_extended_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: nosqlExtendedPatterns.length,
            exec: 'testNoSQLExtended',
            startTime: '50s',
            tags: { category: 'nosql_extended' }
        },
        // Phase 4: API Security patterns (Issue #49)
        api_security_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: apiSecurityPatterns.length,
            exec: 'testAPISecurity',
            startTime: '55s',
            tags: { category: 'api_security' }
        },
        // Phase 5: Pickle Deserialization patterns (Issue #64)
        pickle_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: picklePatterns.length,
            exec: 'testPickle',
            startTime: '60s',
            tags: { category: 'pickle' }
        },
        // Phase 7: Prototype Pollution patterns
        prototype_pollution_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: prototypePollutionPatterns.length,
            exec: 'testPrototypePollution',
            startTime: '65s',
            tags: { category: 'prototype_pollution' }
        },
        // Phase 7: HTTP Smuggling patterns
        http_smuggling_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: httpSmugglingPatterns.length,
            exec: 'testHttpSmuggling',
            startTime: '70s',
            tags: { category: 'http_smuggling' }
        }
    },
    thresholds: {
        'http_req_duration': ['p(95)<5000'],  // 95% of requests under 5s
        'http_req_failed': ['rate<0.05'],      // Less than 5% failure rate
        'attacks_sent': ['count==457']          // All 457 patterns sent (Phase 7 Stage 3)
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

// Phase 2: New category test functions (Issue #780)
export function testLDAP() {
    group('LDAP Injection Tests', function() {
        const pattern = ldapPatterns[scenario.iterationInTest];
        executeAttack(pattern, ldapAttacks);
    });
}

export function testXXE() {
    group('XXE Attack Tests', function() {
        const pattern = xxePatterns[scenario.iterationInTest];
        executeAttack(pattern, xxeAttacks);
    });
}

export function testGraphQL() {
    group('GraphQL Injection Tests', function() {
        const pattern = graphqlPatterns[scenario.iterationInTest];
        executeAttack(pattern, graphqlAttacks);
    });
}

// Phase 3: New category test functions (Issue #783)
export function testXPath() {
    group('XPath Injection Tests', function() {
        const pattern = xpathPatterns[scenario.iterationInTest];
        executeAttack(pattern, xpathAttacks);
    });
}

export function testSSTI() {
    group('SSTI Attack Tests', function() {
        const pattern = sstiPatterns[scenario.iterationInTest];
        executeAttack(pattern, sstiAttacks);
    });
}

export function testNoSQLExtended() {
    group('NoSQL Extended Tests', function() {
        const pattern = nosqlExtendedPatterns[scenario.iterationInTest];
        executeAttack(pattern, nosqlExtendedAttacks);
    });
}

// Phase 4: API Security Tests (Issue #49)
const apiSecurityAttacks = new Counter('api_security_attacks');

export function testAPISecurity() {
    group('API Security Tests', function() {
        const pattern = apiSecurityPatterns[scenario.iterationInTest];
        executeAttack(pattern, apiSecurityAttacks);
    });
}

// Phase 5: Pickle Deserialization Tests (Issue #64)
export function testPickle() {
    group('Pickle Deserialization Tests', function() {
        const pattern = picklePatterns[scenario.iterationInTest];
        executeAttack(pattern, pickleAttacks);
    });
}

// Phase 7: Prototype Pollution Tests
export function testPrototypePollution() {
    group('Prototype Pollution Tests', function() {
        const pattern = prototypePollutionPatterns[scenario.iterationInTest];
        executeAttack(pattern, prototypePollutionAttacks);
    });
}

// Phase 7: HTTP Smuggling Tests
export function testHttpSmuggling() {
    group('HTTP Smuggling Tests', function() {
        const pattern = httpSmugglingPatterns[scenario.iterationInTest];
        executeAttack(pattern, httpSmugglingAttacks);
    });
}

// ========================================
// Setup/Teardown
// ========================================
export function setup() {
    console.log('========================================');
    console.log('k6 E2E Test Starting (Public Repo Mode)');
    console.log(`Target: ${TARGET_IP}:${TARGET_PORT}`);
    console.log('Total Patterns: 457 (Phase 7 Stage 3)');
    console.log('  - SQLi: 124');
    console.log('  - XSS: 86 (+10 Mutation)');
    console.log('  - Path: 76 (+10 Unicode)');
    console.log('  - CmdInj: 89 (+10 Obfuscation)');
    console.log('  - Other: 10');
    console.log('  - LDAP: 10');
    console.log('  - XXE: 8');
    console.log('  - GraphQL: 5');
    console.log('  - XPath: 5');
    console.log('  - SSTI: 10');
    console.log('  - NoSQL Extended: 13');
    console.log('  - API Security: 5');
    console.log('  - Pickle: 4');
    console.log('  - Prototype Pollution: 10 (NEW Phase 7)');
    console.log('  - HTTP Smuggling: 10 (NEW Phase 7)');
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
                other: data.metrics.other_attacks ? data.metrics.other_attacks.values.count : 0,
                // Phase 2: New categories (Issue #780)
                ldap: data.metrics.ldap_attacks ? data.metrics.ldap_attacks.values.count : 0,
                xxe: data.metrics.xxe_attacks ? data.metrics.xxe_attacks.values.count : 0,
                graphql: data.metrics.graphql_attacks ? data.metrics.graphql_attacks.values.count : 0,
                // Phase 3: New categories (Issue #783)
                xpath: data.metrics.xpath_attacks ? data.metrics.xpath_attacks.values.count : 0,
                ssti: data.metrics.ssti_attacks ? data.metrics.ssti_attacks.values.count : 0,
                nosql_extended: data.metrics.nosql_extended_attacks ? data.metrics.nosql_extended_attacks.values.count : 0,
                // Phase 4: API Security (Issue #49)
                api_security: data.metrics.api_security_attacks ? data.metrics.api_security_attacks.values.count : 0,
                // Phase 5: Pickle Deserialization (Issue #64)
                pickle: data.metrics.pickle_attacks ? data.metrics.pickle_attacks.values.count : 0,
                // Phase 7: Prototype Pollution and HTTP Smuggling
                prototype_pollution: data.metrics.prototype_pollution_attacks ? data.metrics.prototype_pollution_attacks.values.count : 0,
                http_smuggling: data.metrics.http_smuggling_attacks ? data.metrics.http_smuggling_attacks.values.count : 0
            }
        }
    };

    const customSummaryForStdout = {
        test_results: completeSummary.test_results,
        test_ids_count: testIdRecords.length
    };

    return {
        'stdout': JSON.stringify(customSummaryForStdout, null, 2),
        // Note: k6 is run from e2e/ directory, so paths are relative to e2e/
        'results/summary.json': JSON.stringify(completeSummary, null, 2),
        'results/test_ids.json': JSON.stringify(testIdRecords, null, 2)
    };
}
