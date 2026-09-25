import http from 'k6/http';
import { check } from 'k6';

// Traffic profiles:
//   keepalive - sustained throughput on reused keep-alive connections (default)
//   churn     - short-lived connections: one fresh TCP connection per iteration
//   mixed     - realistic peak: ramping VUs and a 70/20/10 small/medium/large
//               response mix (~200B / 32KiB / 256KiB bodies)
const KNOWN_PROFILES = ['keepalive', 'churn', 'mixed'];

const targetUrl = __ENV.TARGET_URL || 'http://server:8080/';
const profile = __ENV.PROFILE || 'keepalive';
const vus = parseInt(__ENV.VUS || '10', 10);
const churnRate = parseInt(__ENV.CHURN_RPS || '200', 10);
const duration = __ENV.DURATION || '10s';
// Comma-separated "duration:targetVUs" pairs for the mixed profile ramp.
const mixedStages = __ENV.MIXED_STAGES || '4s:0,6s:50,10s:50,5s:0';
const maxP95Ms = __ENV.MAX_P95_MS || '500';
const maxErrorRate = __ENV.MAX_ERROR_RATE || '0.01';

if (!KNOWN_PROFILES.includes(profile)) {
  throw new Error(`unknown PROFILE '${profile}'; expected one of ${KNOWN_PROFILES.join(', ')}`);
}

function parseStages(spec) {
  return spec.split(',').map((pair) => {
    const [d, t] = pair.split(':');
    return { duration: d.trim(), target: parseInt(t.trim(), 10) };
  });
}

function buildOptions() {
  const base = {
    thresholds: {
      // Correctness guard: requests must succeed without network drops
      http_req_failed: [`rate<${maxErrorRate}`],
      checks: ['rate>0.99'],
      // Generous latency threshold to tolerate CI virtualization scheduling jitter
      http_req_duration: [`p(95)<${maxP95Ms}`],
    },
    // k6's default summaryTrendStats is avg,min,med,max,p(90),p(95) — it omits
    // p(50) and p(99), which compare.py and handleSummary below both require.
    // Pin the full set explicitly so summary.json is complete.
    summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(90)', 'p(95)', 'p(99)'],
    discardResponseBodies: true,
  };

  if (profile === 'churn') {
    // Bound fresh TCP connections per second so repeated runs do not exhaust
    // the attacker's ephemeral ports before TIME_WAIT entries expire.
    return Object.assign({}, base, {
      scenarios: {
        connection_churn: {
          executor: 'constant-arrival-rate',
          rate: churnRate,
          timeUnit: '1s',
          duration: duration,
          preAllocatedVUs: vus,
          maxVUs: vus,
        },
      },
      noConnectionReuse: true,
    });
  }

  if (profile === 'mixed') {
    return Object.assign({}, base, {
      scenarios: {
        mixed_peak: {
          executor: 'ramping-vus',
          startVUs: 0,
          stages: parseStages(mixedStages),
          gracefulRampDown: '0s',
        },
      },
      noConnectionReuse: false,
    });
  }

  return Object.assign({}, base, { vus: vus, duration: duration, noConnectionReuse: false });
}

export const options = buildOptions();

export default function () {
  let url = targetUrl;
  let name = 'KeepAliveTraffic';

  if (profile === 'churn') {
    name = 'ShortLivedConnectionTraffic';
  } else if (profile === 'mixed') {
    const roll = Math.random();
    if (roll < 0.7) {
      url = `${targetUrl}small`;
      name = 'MixedTrafficSmall';
    } else if (roll < 0.9) {
      url = `${targetUrl}medium`;
      name = 'MixedTrafficMedium';
    } else {
      url = `${targetUrl}large`;
      name = 'MixedTrafficLarge';
    }
  }

  const res = http.get(url, {
    tags: { name: name, profile: profile },
    timeout: '3s',
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}

export function handleSummary(data) {
  const summaryPath = __ENV.SUMMARY_PATH || 'summary.json';

  // Format concise stdout text without needing external internet-dependent jslib
  const metric = (m, key) =>
    data.metrics && data.metrics[m] && data.metrics[m].values ? data.metrics[m].values[key] : undefined;

  const reqsRate = (metric('http_reqs', 'rate') || 0).toFixed(1);
  const reqsCount = metric('http_reqs', 'count') || 0;
  const receivedMb = ((metric('data_received', 'count') || 0) / (1024 * 1024)).toFixed(1);
  const p50 = (metric('http_req_duration', 'p(50)') || 0).toFixed(2);
  const p95 = (metric('http_req_duration', 'p(95)') || 0).toFixed(2);
  const p99 = (metric('http_req_duration', 'p(99)') || 0).toFixed(2);
  const failRate = ((metric('http_req_failed', 'rate') || 0) * 100).toFixed(2);
  const vusMax = metric('vus_max', 'value') || vus;

  const stdoutSummary =
    `[k6:${profile}] requests=${reqsCount} rate=${reqsRate} req/s | ` +
    `p50=${p50}ms p95=${p95}ms p99=${p99}ms | errors=${failRate}% | ` +
    `vus_max=${vusMax} rx=${receivedMb}MiB\n`;

  return {
    [summaryPath]: JSON.stringify(data, null, 2),
    stdout: stdoutSummary,
  };
}
