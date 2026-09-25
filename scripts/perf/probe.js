import http from 'k6/http';
import { check } from 'k6';

const targetUrl = __ENV.TARGET_URL;
const mode = __ENV.MODE || 'allowed';
const expectedStatus = parseInt(__ENV.EXPECTED_STATUS || '200', 10);

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: {
    checks: ['rate==1'],
  },
};

export default function () {
  const response = http.get(targetUrl, { timeout: '2s' });
  const passed = mode === 'blocked'
    ? response.status === 0
    : response.status === expectedStatus;

  check(response, {
    [`${mode} response from ${targetUrl}`]: () => passed,
  });
}
