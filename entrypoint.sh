#!/bin/sh -l

set -e

export VT_API_KEY="${INPUT_API_KEY}"
export VT_SCAN_PATHS="${INPUT_SCAN_PATHS}"
export VT_NO_CACHE="${INPUT_NO_CACHE}"
export VT_CACHE_PATH="${INPUT_CACHE_PATH}"
export VT_WHITELIST_PATH="${INPUT_WHITELIST_PATH}"
export VT_REPORT_PATH="${INPUT_REPORT_PATH}"
export VT_REQUEST_INTERVAL_SEC="${INPUT_REQUEST_INTERVAL_SEC}"
export VT_ANALYSIS_POLL_TIMEOUT_SEC="${INPUT_ANALYSIS_POLL_TIMEOUT_SEC}"
export VT_DOWNLOAD_TIMEOUT_SEC="${INPUT_DOWNLOAD_TIMEOUT_SEC}"
export VT_MAX_REPORT_AGE_DAYS="${INPUT_MAX_REPORT_AGE_DAYS}"

if [ "${GITHUB_ACTIONS}" = "true" ]; then
  export USE_GITHUB_ACTION_REPORTER=true
fi

python -m virustotal_scan
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
