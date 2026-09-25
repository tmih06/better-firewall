import http from 'k6/http';
import { check } from 'k6';

const targetUrl = __ENV.TARGET_URL || 'http://10.200.1.1:8080/';
const vus = parseInt(__ENV.VUS || '10', 10);
const duration = __ENV.DURATION || '5s';

export const options = {
  vus: vus,
  duration: duration,
  thresholds: {
    // Correctness guard: requests must succeed without network drops
    http_req_failed: ['rate<0.01'],
    // Generous latency threshold to tolerate CI virtualization scheduling jitter
    http_req_duration: ['p(95)<500'],
  },
  // k6's default summaryTrendStats is avg,min,med,max,p(90),p(95) — it omits
  // p(50) and p(99), which compare.py and handleSummary below both require.
  // Pin the full set explicitly so summary.json is complete.
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(90)', 'p(95)', 'p(99)'],
  noConnectionReuse: false,
  discardResponseBodies: true,
};

export default function () {
  const res = http.get(targetUrl, {
    tags: { name: 'TraversedFirewallTraffic' },
    timeout: '3s',
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}

export function handleSummary(data) {
  const summaryPath = __ENV.SUMMARY_PATH || 'summary.json';

  // Format concise stdout text without needing external internet-dependent jslib
  const reqsRate =
    data.metrics && data.metrics.http_reqs && data.metrics.http_reqs.values
      ? data.metrics.http_reqs.values.rate.toFixed(1)
      : '0.0';
  const reqsCount =
    data.metrics && data.metrics.http_reqs && data.metrics.http_reqs.values
      ? data.metrics.http_reqs.values.count
      : 0;
  const p50 =
    data.metrics && data.metrics.http_req_duration && data.metrics.http_req_duration.values
      ? (data.metrics.http_req_duration.values['p(50)'] || 0).toFixed(2)
      : 'N/A';
  const p95 =
    data.metrics && data.metrics.http_req_duration && data.metrics.http_req_duration.values
      ? (data.metrics.http_req_duration.values['p(95)'] || 0).toFixed(2)
      : 'N/A';
  const p99 =
    data.metrics && data.metrics.http_req_duration && data.metrics.http_req_duration.values
      ? (data.metrics.http_req_duration.values['p(99)'] || 0).toFixed(2)
      : 'N/A';
  const failRate =
    data.metrics && data.metrics.http_req_failed && data.metrics.http_req_failed.values
      ? (data.metrics.http_req_failed.values.rate * 100).toFixed(2)
      : '0.00';

  const stdoutSummary =
    `[k6] requests=${reqsCount} rate=${reqsRate} req/s | ` +
    `p50=${p50}ms p95=${p95}ms p99=${p99}ms | errors=${failRate}%\n`;

  return {
    [summaryPath]: JSON.stringify(data, null, 2),
    stdout: stdoutSummary,
  };
}
