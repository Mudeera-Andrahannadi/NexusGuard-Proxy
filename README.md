# NexusGuard Proxy

NexusGuard Proxy is a forward proxy for HTTP and HTTPS written in plain Java 17, with no third-party dependencies. It sits between the clients on a private network and the internet, and it does three jobs at once: it relays traffic, it blocks clients and requests that look hostile, and it keeps a metadata-only record of every connection that a read-only dashboard turns into something an operator can watch.

- **Proxying.** HTTP `GET` and `HEAD`, and HTTPS through `CONNECT` tunnels. Tunnels are never decrypted.
- **Protection.** Per-client rate limiting with automatic, temporary IP blocks, plus signature checks for directory traversal, SQL injection, cross-site scripting and known scanner tools.
- **Visibility.** One JSONL record per connection attempt, and a dashboard with live alerts, a blocked-clients panel and filterable history.
- **Deployment.** Runs from source with two scripts, or in a container with `docker compose up`.

## Contents

- [How a request is handled](#how-a-request-is-handled)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Run with Docker Compose](#run-with-docker-compose)
- [Configuration](#configuration)
- [Detection](#detection)
- [Dashboard](#dashboard)
- [Event log](#event-log)
- [Multi-client demo](#multi-client-demo)
- [Tests](#tests)
- [Scope and limits](#scope-and-limits)
- [Troubleshooting](#troubleshooting)
- [Contributors](#contributors)

## How a request is handled

Each connection goes through the same checks, in this order. The first one that refuses it ends the exchange.

1. **Client allowlist.** In network mode, a client that is not on the allowlist gets `403` and is not logged.
2. **Rate limit.** A client over its allowance gets `429`. The block is logged once, when it starts.
3. **Signature scan.** The request target and `User-Agent` are checked against known attack patterns. A match gets `403`.
4. **Request validation.** Bodies, malformed requests, and mismatched or duplicate `Host` headers are refused.
5. **Destination policy.** Addresses on internal networks, such as the cloud metadata address `169.254.169.254`, are refused.
6. **Relay.** The proxy connects to the destination and passes bytes in both directions.

Every outcome from step 2 onward produces one log record.

## Architecture

```
 client 1 ──┐      ┌────────────────────────────────────────┐
            ├─────►│ ForwardProxyServer            :8888    │ ─────► destination
 client 2 ──┘      │   ClientGuard        rate limit        │
                   │   SignatureScanner   attack patterns   │
                   └────────────────────────────────────────┘
                                       │ FlowEvent
                                       ▼
                   ┌────────────────────────────────────────┐
                   │ EventLog    data/proxy-events.jsonl    │
                   │            latest 500 kept in memory   │
                   └────────────────────────────────────────┘
                                       │ /api/*
                                       ▼
                   ┌────────────────────────────────────────┐
    browser ──►    │ DashboardServer        127.0.0.1:8181  │
                   └────────────────────────────────────────┘

                   LocalDemoSite   127.0.0.1:9090   (local test destination)
```

| Component | Package | Responsibility |
| --- | --- | --- |
| `NetGuardApp` | `com.demo.netguard` | Starts the services, reads command-line flags and the allowlist |
| `ForwardProxyServer` | `.proxy` | Accepts clients, applies the checks above, relays HTTP and tunnels HTTPS |
| `ClientGuard` | `.security` | Sliding-window rate limit per client IP, with timed blocks |
| `SignatureScanner` | `.security` | Matches request targets and `User-Agent` values against attack signatures |
| `FlowEvent` | `.model` | The record written for each connection attempt |
| `EventLog` | `.monitor` | Thread-safe JSONL writer with size-based rotation and replay on startup |
| `DashboardServer` | `.monitor` | Read-only JSON API and the single-page dashboard |
| `LocalDemoSite` | `.demo` | A small loopback website used as a test destination |

## Quick start

You need JDK 17 or newer with `javac` and `java` on your `PATH`. Nothing else is required. The demo script also uses `curl`, which ships with Windows 10 and later.

Clone and run:

```bash
git clone https://github.com/Mudeera-Andrahannadi/netproxy-logger.git
cd netproxy-logger
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run.ps1
```

Linux and macOS:

```bash
bash scripts/run.sh
```

The scripts compile the project first, then start it. The proxy listens on `127.0.0.1:8888` and the dashboard on `http://127.0.0.1:8181`. Stop it with Ctrl+C.

Send a request through the proxy to the built-in demo site:

```bash
curl -x http://127.0.0.1:8888 http://127.0.0.1:9090/
```

Refresh the dashboard and you will see a `Connected` row. If nothing appears, see [`NO_PROXY`](#troubleshooting) below.

To see the detection work, send two requests that should be refused:

```bash
curl --path-as-is -x http://127.0.0.1:8888 "http://127.0.0.1:9090/../../etc/passwd"
curl -A sqlmap -x http://127.0.0.1:8888 http://127.0.0.1:9090/
```

Both return `403` and appear as red rows on the dashboard.

## Run with Docker Compose

The image compiles the application in a JDK 17 stage and runs it on a JRE 17 Alpine image as a non-root user, with a read-only root filesystem, all Linux capabilities dropped, and a health check on the dashboard.

```bash
docker compose up --build -d
```

| What | Where |
| --- | --- |
| Dashboard | `http://127.0.0.1:8181` |
| Proxy | `127.0.0.1:8888` |
| Event log | The `netguard-data` volume, mounted at `/app/data` |

```bash
curl -x http://127.0.0.1:8888 http://example.com/
```

Use a real site for this check. The demo website listens on the container's own loopback and cannot be reached from outside.

Useful commands:

| Command | Effect |
| --- | --- |
| `docker compose ps` | Shows `healthy` once the dashboard answers |
| `docker compose logs -f` | Follows the application output |
| `docker compose down` | Stops the stack and keeps the event log |
| `docker compose down -v` | Stops the stack and deletes the event log |

The detection settings are the `command:` line in `docker-compose.yml`. Change them and run `docker compose up -d` again.

### Client addresses in Docker

The proxy only serves clients on its allowlist, so inside a container the list has to match the addresses Docker presents. Requests sent from the Docker host arrive from the network gateway, `172.28.0.1`, which is what `config/docker-allowed-clients.txt` contains by default. The compose file pins the network to `172.28.0.0/24` so that address does not change. If the range collides with something on your network, change it in `docker-compose.yml` and in the allowlist.

By default the proxy is published to `127.0.0.1` only. To serve other machines, publish it on this host's LAN address and add each client to the allowlist:

```bash
PROXY_HOST_IP=192.168.1.20 docker compose up -d
```

```powershell
$env:PROXY_HOST_IP = '192.168.1.20'; docker compose up -d
```

Docker Desktop on Windows and macOS can replace the address of outside clients with the gateway address. When that happens, all of them appear as one client and share one rate limit and one block. Docker Engine on Linux preserves the real addresses. If you need distinct client addresses on Windows, run the application directly instead.

The dashboard is always published to `127.0.0.1` only. It has no login.

## Configuration

### Command-line flags

Pass flags to `scripts/run.ps1` or `scripts/run.sh`, or to the `command:` list in `docker-compose.yml`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--bind <ip>` | `127.0.0.1` | Address the proxy listens on. A loopback or private IPv4 address; `0.0.0.0` is refused |
| `--dashboard-bind <ip>` | `127.0.0.1` | Address the dashboard listens on, under the same rule |
| `--max-requests <n>` | `100` | Connections one client may open within the window |
| `--window <seconds>` | `10` | Length of the sliding window |
| `--block <seconds>` | `60` | How long a client stays blocked once it exceeds the limit |

For example, a strict setting for a demo:

```bash
bash scripts/run.sh --max-requests 20 --window 5 --block 30
```

### Allowlist

When `--bind` is a private network address, the proxy refuses to start unless `config/allowed-lan-clients.txt` lists at least one client. Put one private IPv4 address per line. Lines starting with `#` are comments. Any client not on the list receives `403`.

On loopback the allowlist is not enforced, because only the local machine can connect.

### Ports

| Port | Service | Reachable from |
| --- | --- | --- |
| 8888 | Proxy | The address given to `--bind` |
| 8181 | Dashboard | The address given to `--dashboard-bind`, loopback by default |
| 9090 | Demo website | This machine only |

## Detection

### Rate limiting

`ClientGuard` keeps a sliding window of connection times for each client IP. A client that opens more than `--max-requests` connections inside `--window` seconds is blocked for `--block` seconds. While blocked, it receives `429 Too Many Requests`. The block lifts by itself when the time is up.

The block is written to the log once, when it begins. Later refused connections are answered but not logged, so a flood cannot push genuine events out of the dashboard's history.

### Signature scanning

`SignatureScanner` checks the request target and the `User-Agent` header of each plain HTTP request, after percent-decoding the target up to three times to catch encoded variants.

| Category | What it looks for |
| --- | --- |
| Directory traversal | `../` and `..\` sequences, plain or encoded, and a path that ends in `/..` |
| SQL injection | Quote-based tautologies such as `' OR 1=1`, `UNION SELECT`, `DROP TABLE`, a quote followed by `--`, and `SLEEP()`, `BENCHMARK()` or `WAITFOR DELAY` |
| Cross-site scripting | `script`, `iframe`, `object` and `embed` tags, `javascript:` URIs, inline handlers such as `onerror=`, and `document.cookie` |
| Scanner tools | `User-Agent` values naming `nmap`, `nikto`, `sqlmap`, `dirbuster`, `gobuster`, `masscan`, `wpscan`, `hydra`, `acunetix` or `nessus` |

A match returns `403` and is logged with the category. The matched text is not logged, so an attack string cannot end up in the record.

### Reason codes

| Reason | Meaning | Dashboard label |
| --- | --- | --- |
| `RATE_LIMIT_EXCEEDED` | The client went over its allowance and is now blocked | Blocked · Rate limit |
| `MALICIOUS_PATTERN_DETECTED:DIRECTORY_TRAVERSAL` | Path traversal in the request target | Blocked · Directory traversal |
| `MALICIOUS_PATTERN_DETECTED:SQL_INJECTION` | SQL injection syntax in the request target | Blocked · SQL injection |
| `MALICIOUS_PATTERN_DETECTED:XSS` | Script injection in the request target | Blocked · Cross-site scripting |
| `MALICIOUS_PATTERN_DETECTED:SCANNER_USER_AGENT` | A known scanning tool in the `User-Agent` | Blocked · Scanner agent |
| `DESTINATION_POLICY` and other rules | The request broke a safety rule, such as an internal destination | Denied · plus the rule |

Outcomes are `CONNECTED` (the connection to the destination opened, whatever the response was), `FAILED` (the destination could not be reached) and `DENIED` (the proxy refused the request).

## Dashboard

The dashboard is a single page served by `DashboardServer` with no external assets. It refreshes every few seconds.

- **Alert banner.** Appears when threats were blocked in the last minute or any client is currently blocked. The browser tab title carries the count.
- **Summary tiles.** Threats blocked, clients blocked now, the most common threat, and connection totals.
- **Clients panel.** Every client with its request and threat counts. Blocked clients show a live countdown until the block lifts.
- **Recent alerts.** The latest blocked requests with the category and client.
- **Connections table.** Newest first, with filters for client IP, domain, time range and result type (all, threats only, policy denials only).

The tiles, panel and alerts follow the selected time range. Threat counts are computed in the browser from the latest 500 events.

### API

All endpoints are read-only.

| Endpoint | Returns |
| --- | --- |
| `/api/events?client=&domain=&limit=` | Matching events as a JSON array, oldest first. `client` is an exact IP, `domain` a case-insensitive substring, `limit` defaults to 100 and is capped at 500 |
| `/api/summary` | Counts of connected, failed and denied events among the retained ones |
| `/api/blocked` | Clients blocked now, as `[{"ip":"...","remainingSeconds":n}]` |
| `/api/status` | `{"storage":"ok"}` or `{"storage":"error"}`, depending on whether the log can be written |
| `/health` | `ok` |

## Event log

Events are appended to `data/proxy-events.jsonl`, one JSON object per line:

```json
{"at":"2026-11-10T08:00:00Z","sourceIp":"192.0.2.10","method":"GET","destination":"example.com","port":80,"protocol":"HTTP","outcome":"CONNECTED","reason":"UPSTREAM_TCP_CONNECTED"}
```

The log holds connection metadata only: time, client IP, method, destination host and port, protocol, outcome and reason. It never stores URL paths, query strings, headers, cookies or bodies.

The active file and three archives are each capped at 1 MiB, so the log keeps about 4 MiB of history. On startup the latest 500 events are loaded back into memory for the dashboard. If the log cannot be written, the dashboard shows a warning banner and keeps serving what it has in memory.

## Multi-client demo

This shows two devices using the proxy at the same time, each appearing as its own client. Client 1 is the machine running the proxy. Client 2 is a phone or another laptop on the same network. Some guest and campus networks stop devices from reaching each other; use a hotspot or a home router if that happens.

1. **Find the addresses.** Run `ipconfig` (or `ip addr`) on the proxy machine for its private IPv4 address, `PC_IP`. Note the second device's address as `PHONE_IP`.
2. **Allow both clients.** Add them to `config/allowed-lan-clients.txt`, one per line.
3. **Start on the LAN address.**

   ```bash
   bash scripts/run.sh --bind PC_IP
   ```

   On Windows, allow Java through the firewall for private networks when asked. Open the dashboard on the proxy machine at `http://127.0.0.1:8181`.
4. **Send traffic from client 1.**

   ```bash
   bash scripts/demo-traffic.sh PC_IP
   ```

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/demo-traffic.ps1 -Proxy PC_IP
   ```

   The script sends three requests: `http://example.com/` returns `200`, `https://example.org/` returns `200` through a tunnel, and `http://169.254.169.254/` returns `403`. The first two need internet access.
5. **Point client 2 at the proxy.** In the device's Wi-Fi settings set a manual proxy with host `PC_IP` and port `8888`, then browse a few sites.
6. **Read the dashboard.** Rows from both addresses appear. Filter by `PHONE_IP` to isolate the second device, or send a burst of requests from it to watch it get blocked and the countdown start.

When you finish, remove the proxy setting from the device and from Windows if you set it system-wide, or that machine will lose internet access once the proxy stops.

## Tests

The tests are plain Java classes with a `main` method, so no test framework is needed. The scripts build the project and run every class:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test.ps1
```

```bash
bash scripts/test.sh
```

| Class | Covers |
| --- | --- |
| `SmokeTest` | Proxy, tunnel, denials, logging and dashboard working together on loopback |
| `ForwardProxyServerTest` | Request validation, allowlist, size limits and malformed input |
| `ClientGuardTest` | Rate window, blocking and unblocking on a fake clock, concurrency, and a real proxy answering `429` |
| `SignatureScannerTest` | Each attack category, encoded variants, and ordinary requests that must pass |
| `EventLogTest` | JSON escaping, replay, rotation, concurrent writes and write failures |
| `DashboardServerTest` | Query parsing, the API endpoints, bind-address rules and the page contract |

Run the scripts from any directory. They switch to the repository root first, because `EventLogTest` reads `docs/examples/synthetic-proxy-events.jsonl`. On Windows use `test.ps1`: `test.sh` passes a `:` classpath separator, which Windows Java does not accept.

The dashboard's filters and countdown are JavaScript in the page, so the tests only check that the page ships them. Check them by hand in a browser.

GitHub Actions runs `scripts/test.sh` on every push to `main`, `dev` and `feature/**`, and on pull requests into `dev` and `main`.

## Scope and limits

NexusGuard is built for networks you control. Please keep these in mind before deploying it.

- The proxy handles `GET`, `HEAD` and `CONNECT`. Requests with a body, such as `POST`, are rejected.
- HTTPS is tunnelled without inspection. For those connections the scanner only sees the `User-Agent` of the `CONNECT` request, never the path.
- Signature scanning is pattern matching on the request line and one header. It is not a web application firewall, and it will miss attacks it has no pattern for.
- There is no authentication and no per-user identity. A client is the IP address the proxy saw.
- Blocks are held in memory, so restarting the proxy lifts them. The dashboard is read-only and has no unblock control.
- The dashboard has no login. Keep it on loopback, or on a private interface that only administrators can reach.
- The proxy refuses to bind to `0.0.0.0`. Do not expose it to the internet.

## Troubleshooting

**A request does not show up on the dashboard.** Check the `NO_PROXY` environment variable first. Many setups list `127.0.0.1` there, and curl then skips the proxy without saying so. Clear it for the command: `NO_PROXY= curl -x ...` in bash, or `$env:NO_PROXY=''` first in PowerShell. Then confirm the client really uses port 8888 and, in network mode, that its address is on the allowlist.

**The proxy will not start on a network address.** The allowlist is empty or contains an address that is not a private IPv4 literal. Fix `config/allowed-lan-clients.txt`.

**A client gets `429`.** It went over `--max-requests` within `--window` seconds. The dashboard shows how long the block has left. Raise the limit, or restart the proxy to lift the block immediately.

**`scripts/test.sh` cannot find a class on Windows.** Use `scripts/test.ps1` instead.

**`docker compose up` fails because the subnet is in use.** Change `172.28.0.0/24` in `docker-compose.yml`, and update the gateway address in `config/docker-allowed-clients.txt` to match.

## Contributors

| | Name | Role |
| --- | --- | --- |
| Dev 1 | Vidasun Fernando | Forward proxy |
| Dev 2 | Pramith Vidanapathirana | Event logging |
| Dev 3 | Mudeera Andrahannadi | Dashboard, integration, security layer and deployment |
