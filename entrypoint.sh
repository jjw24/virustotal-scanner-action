#!/bin/sh -l

set -e

export VT_API_KEY="$(printenv INPUT_API_KEY || printenv INPUT_API-KEY || true)"
export VT_SCAN_PATHS="$(printenv INPUT_SCAN_PATHS || printenv INPUT_SCAN-PATHS || true)"
export VT_NO_CACHE="$(printenv INPUT_NO_CACHE || printenv INPUT_NO-CACHE || true)"
export VT_CACHE_PATH="$(printenv INPUT_CACHE_PATH || printenv INPUT_CACHE-PATH || true)"
export VT_WHITELIST_PATH="$(printenv INPUT_WHITELIST_PATH || printenv INPUT_WHITELIST-PATH || true)"
export VT_REPORT_PATH="$(printenv INPUT_REPORT_PATH || printenv INPUT_REPORT-PATH || true)"
export VT_REQUEST_INTERVAL_SEC="$(printenv INPUT_REQUEST_INTERVAL_SEC || printenv INPUT_REQUEST-INTERVAL-SEC || true)"
export VT_ANALYSIS_POLL_TIMEOUT_SEC="$(printenv INPUT_ANALYSIS_POLL_TIMEOUT_SEC || printenv INPUT_ANALYSIS-POLL-TIMEOUT-SEC || true)"
export VT_DOWNLOAD_TIMEOUT_SEC="$(printenv INPUT_DOWNLOAD_TIMEOUT_SEC || printenv INPUT_DOWNLOAD-TIMEOUT-SEC || true)"
export VT_MAX_REPORT_AGE_DAYS="$(printenv INPUT_MAX_REPORT_AGE_DAYS || printenv INPUT_MAX-REPORT-AGE-DAYS || true)"

if [ "${GITHUB_ACTIONS}" = "true" ]; then
  export USE_GITHUB_ACTION_REPORTER=true
fi

python3 -m virustotal_scan
PY_EXIT=$?

REPORT_PATH="${VT_REPORT_PATH:-vt_report.json}"
echo "report-path=${REPORT_PATH}" >> "${GITHUB_OUTPUT}"

if [ -f "${REPORT_PATH}" ]; then
  TOTAL=$(python3 -c "import json,sys; d=json.load(open('${REPORT_PATH}')); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
  PASSED=$(python3 -c "import json,sys; d=json.load(open('${REPORT_PATH}')); print(sum(1 for r in d.get('results',[]) if r.get('passed')))" 2>/dev/null || echo "0")
  FAILED=$(python3 -c "import json,sys; d=json.load(open('${REPORT_PATH}')); print(sum(1 for r in d.get('results',[]) if not r.get('passed')))" 2>/dev/null || echo "0")
else
  TOTAL="0"
  PASSED="0"
  FAILED="0"
fi

echo "exit-code=${PY_EXIT}" >> "${GITHUB_OUTPUT}"
echo "passed-count=${PASSED}" >> "${GITHUB_OUTPUT}"
echo "failed-count=${FAILED}" >> "${GITHUB_OUTPUT}"
echo "total-count=${TOTAL}" >> "${GITHUB_OUTPUT}"

exit ${PY_EXIT}
