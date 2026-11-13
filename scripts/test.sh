#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/build.sh
# EventLogTest reads docs/examples, so every test runs from the repo root.
for t in SmokeTest monitor.EventLogTest monitor.DashboardServerTest proxy.ForwardProxyServerTest security.ClientGuardTest; do
  echo "== $t"
  java -cp build/main:build/test "com.demo.netguard.$t"
done
