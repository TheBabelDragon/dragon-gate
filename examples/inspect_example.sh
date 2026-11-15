#!/usr/bin/env bash
# Example: Redirect Observatory against a public site (optional; tests use fixtures)
set -euo pipefail
dragon-gate inspect https://example.com --json
dragon-gate dns example.com --json
dragon-gate tls example.com --json
