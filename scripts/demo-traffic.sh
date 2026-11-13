#!/usr/bin/env bash
# Sends a few typical requests through the proxy from this machine (client 1).
# Usage: bash scripts/demo-traffic.sh <proxy-ip>
set -u
px="http://${1:?usage: demo-traffic.sh <proxy-ip>}:8888"
# NO_PROXY often lists 127.0.0.1, which would make curl skip the proxy.
export NO_PROXY= no_proxy=
curl -s -o /dev/null -w "HTTP   example.com           -> %{http_code}\n" -x "$px" http://example.com/
curl -s -o /dev/null -w "HTTPS  example.org (CONNECT) -> %{http_code}\n" -x "$px" https://example.org/
curl -s -o /dev/null -w "BLOCKED 169.254.169.254      -> %{http_code} (expected 403)\n" -x "$px" http://169.254.169.254/
