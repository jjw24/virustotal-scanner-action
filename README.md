# VirusTotal Scanner Action

GitHub Acion to scan files with [VirusTotal](https://www.virustotal.com), view results directly in the job output, and automatically pass or fail based on the scan outcome.

No need to visit VirusTotal website or writing custom pass/fail logic. Every scan verdict is shown inline in your workflow run, and the step succeeds or fails based on detection results.

**Free API tier friendly.** The action throttles to 15 seconds between requests by default- matching VirusTotal's free-tier limit of 4 requests per minute. A file hash-first lookup checks for existing reports before uploading, so already-scanned files skip the expensive upload step and return results faster. A local cache (`vt_cache.json`) further reduces repeat API calls across workflow runs. Cached results older than 30 days are automatically discarded (configurable via `max-report-age-days`), ensuring scans use relatively recent analysis data.

**Premium API ready.** If you have a VirusTotal Premium API key, set a lower `request-interval-sec` (e.g. `"1"`) for faster scans. The action also respects `Retry-After` headers and uses exponential backoff, so it plays well at any tier without manual tuning.

## Table of Contents

- [Usage](#usage)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Example workflow](#example-workflow)
- [Whitelisting](#whitelisting)

## Usage

```yaml
- uses: jjw24/virustotal-scanner-action@v1
  with:
    api-key: ${{ secrets.VT_API_KEY }}
    scan-paths: ./path/to/file,./directory/
```

The step fails when any file is detected. No additional `exit 1` checks needed.

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `api-key` | **yes** | - | VirusTotal API key |
| `scan-paths` | **yes** | - | Comma- or newline-separated file or directory paths to scan |
| `no-cache` | no | `false` | Skip cache lookup (set to `"true"` to bypass) |
| `cache-path` | no | `vt_cache.json` | Path to cache file (relative to workspace root) |
| `whitelist-path` | no | `vt_whitelist.json` | Path to whitelist file (relative to workspace root) |
| `report-path` | no | `vt_report.json` | Path to write JSON report output (relative to workspace root) |
| `request-interval-sec` | no | `15` | Minimum seconds between VT API requests |
| `analysis-poll-timeout-sec` | no | `600` | Maximum seconds to wait for VT analysis to complete |
| `download-timeout-sec` | no | `120` | Timeout in seconds for file uploads to VT |
| `max-report-age-days` | no | `30` | Discard cached VT reports and local cache entries older than this many days, forcing a fresh scan. Set to `0` to accept any age |

## Outputs

| Name | Description |
|------|-------------|
| `exit-code` | Pipeline exit code (`0` = all passed, `1` = some failed) |
| `report-path` | Path to the generated JSON report file |
| `passed-count` | Number of files that passed the scan |
| `failed-count` | Number of files that failed the scan |
| `total-count` | Total number of files scanned |

Reference outputs from later steps using `${{ steps.<step-id>.outputs.<name> }}`:

```yaml
- uses: jjw24/virustotal-scanner-action@v1
  id: vt-scan
  with:
    api-key: ${{ secrets.VT_API_KEY }}
    scan-paths: ./files/

- name: Show summary
  run: |
    echo "Passed: ${{ steps.vt-scan.outputs.passed-count }}"
    echo "Failed: ${{ steps.vt-scan.outputs.failed-count }}"
    echo "Total:  ${{ steps.vt-scan.outputs.total-count }}"
```

## Example workflow

```yaml
name: VirusTotal Scan

on:
  workflow_dispatch:
  push:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      # Restore VT cache from previous run (optional- speeds up repeat scans)
      - uses: actions/cache/restore@v5
        with:
          path: vt_cache.json
          key: vt-cache-${{ github.sha }}
          restore-keys: vt-cache-

      - uses: jjw24/virustotal-scanner-action@v1
        with:
          api-key: ${{ secrets.VT_API_KEY }}
          scan-paths: |
            ./downloaded-artifacts/
            ./vendor/bin/
          no-cache: false
          cache-path: vt_cache.json
          whitelist-path: vt_whitelist.json
          report-path: vt_report.json
          request-interval-sec: 15
          analysis-poll-timeout-sec: 600
          download-timeout-sec: 120
          max-report-age-days: 30

      # Save cache for next run
      - uses: actions/cache/save@v5
        if: always()
        with:
          path: vt_cache.json
          key: vt-cache-${{ github.sha }}

      # Upload report file as raw viewable json
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          path: vt_report.json
          archive: false

      # Upload cache file as raw viewable json
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          path: vt_cache.json
          archive: false
```

## Whitelisting

Create a `vt_whitelist.json` file in your repository to suppress known false positives.
An entry must exactly match the VirusTotal scan result- same SHA-256, the same set of engine threats with identical labels, and the same sandbox flags. Inspect the action output or JSON report to see the exact values for a detected file:

```json
[
  {
    "sha256": "a1b2c3...",
    "engine_threats": {
      "EngineA": "Trojan.Generic",
      "EngineB": "Malware.Launcher"
    },
    "sandbox_flags": ["Example Sandbox (malicious)"]
  }
]
```
