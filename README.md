# NexusGuard Proxy
Team Members:
* Dev 1 (Forward Proxy):** Vidasun Fernando
* Dev 2 (Event Logging):** Pramith Vidanapathirana
* Dev 3 (Dashboard & Integration): Mudeera Andrahannadi

A small forward proxy written in plain Java 17. It relays HTTP and HTTPS traffic for LAN clients, writes one metadata record per connection to a JSONL file, and shows the recent records on a dashboard that only listens on localhost.

This is Phase 1 of a university networking project. It records who connected to what and whether it worked. It does not inspect traffic, and it does not decide whether anything is an attack: there is no intrusion detection here. It is meant for an isolated lab, not for production or for the open internet.

## What it does

- Proxies HTTP `GET` and `HEAD` requests, and HTTPS through `CONNECT` tunnels. The tunnel is blind: TLS is never decrypted.
- Logs one record per connection attempt: time, client IP, method, destination host, port, protocol, outcome and a short reason. It never stores URL paths, query strings, headers, cookies or bodies.
- Refuses destinations on internal networks (for example `169.254.169.254`), requests with bodies, mismatched or duplicate `Host` headers, and malformed requests.
- Serves a read-only dashboard at `http://127.0.0.1:8181` with a client filter, a domain filter, a time range filter, and messages for empty and storage-error states.
- Ships a loopback demo website so the whole thing can be tried without touching the internet.

## Architecture

```
 LAN client 1 ──┐                         ┌──────────────────────────────┐
                ├── HTTP / CONNECT ─────► │  ForwardProxyServer  :8888   │ ───► destination
 LAN client 2 ──┘                         │  (checks, relays, no TLS     │      (example.com, ...)
                                          │   inspection)                │
                                          └──────────────┬───────────────┘
                                                         │ FlowEvent
                                                         ▼
                                          ┌──────────────────────────────┐
                                          │  EventLog                    │
                                          │  data/proxy-events.jsonl     │
                                          │  last 500 events in memory   │
                                          └──────────────┬───────────────┘
                                                         │ /api/events, /api/summary, /api/status
                                                         ▼
                                          ┌──────────────────────────────┐
                              browser ──► │  DashboardServer  127.0.0.1  │
                              (this PC)   │  :8181 (localhost only)      │
                                          └──────────────────────────────┘

                                          LocalDemoSite  127.0.0.1:9090  (test destination)
```

| Part | Where | Job |
| --- | --- | --- |
| `NetGuardApp` | `src/main/java/com/demo/netguard/` | Starts everything, reads `--bind` and the client allowlist |
| `ForwardProxyServer` | `.../proxy/` | Accepts clients, validates requests, relays HTTP and tunnels HTTPS |
| `FlowEvent` | `.../model/` | The record written for each connection attempt |
| `EventLog` | `.../monitor/` | Thread-safe JSONL writer. Rotates at 1 MiB with 3 archives, and replays the latest 500 events on startup |
| `DashboardServer` | `.../monitor/` | Read-only JSON API and the single-page viewer |
| `LocalDemoSite` | `.../demo/` | A tiny loopback website to use as a test destination |

Ports:

| Port | What | Reachable from |
| --- | --- | --- |
| 8888 | Proxy | The address passed to `--bind` (default `127.0.0.1`) |
| 8181 | Dashboard | This machine only |
| 9090 | Demo website | This machine only |

### Outcomes in the log

`CONNECTED` means the connection to the destination opened. It does not mean the HTTP response was a success. `FAILED` means the destination could not be reached. `DENIED` means the proxy's safety rules said no, for example an internal address. A denied request is a policy decision, not a verdict that something was malicious.

A client whose IP is not on the allowlist gets a `403` and no log record.

## Requirements

- JDK 17 or newer (`javac` and `java` on your PATH). There are no other dependencies.
- Windows PowerShell 5.1 or later, or bash on Linux and macOS.
- `curl` for the demo script. Windows 10 and later include `curl.exe`.

## Build and run

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
powershell -ExecutionPolicy Bypass -File scripts/run.ps1
```

Linux and macOS:

```bash
bash scripts/build.sh
bash scripts/run.sh
```

`run` builds first, so you can skip the separate build step. On start it prints the proxy address and the dashboard URL. Stop it with Ctrl+C.

By default the proxy listens on `127.0.0.1` only. To let other devices on your network use it, see the demo below.

### Quick check on one machine

With the app running, send a request through the proxy to the demo website:

```bash
curl -x http://127.0.0.1:8888 http://127.0.0.1:9090/
```

Then open `http://127.0.0.1:8181`. You should see one `CONNECTED` row.

If nothing shows up, check the `NO_PROXY` environment variable. Many setups list `127.0.0.1` there, and curl then skips the proxy without telling you. Clear it for the command: `NO_PROXY= curl -x ...` in bash, or `$env:NO_PROXY=''` first in PowerShell.

## Tests

The tests are plain Java classes with a `main` method, no test framework needed. The scripts build the project and run all four in turn:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test.ps1
```

```bash
bash scripts/test.sh
```

| Class | Covers |
| --- | --- |
| `SmokeTest` | Proxy, tunnel, denials, logging and dashboard together on loopback |
| `EventLogTest` | JSON escaping, replay, rotation, concurrent writes, write failures |
| `DashboardServerTest` | Filter parsing, `/api/status`, and the messages the page ships with |
| `ForwardProxyServerTest` | Request validation, allowlist, limits and malformed input |

Run the scripts from anywhere: they switch to the repository root first, which `EventLogTest` needs because it reads `docs/examples/synthetic-proxy-events.jsonl`. On Windows use `test.ps1`; `test.sh` is meant for Linux and CI because of how Java reads the classpath there.

The time range filter is JavaScript in the page, so it is not covered by these tests. Check it by hand in a browser.

GitHub Actions runs `scripts/test.sh` on every push to `main`, `dev` and `feature/**`, and on pull requests into `dev` and `main`.

## Two-client demo

This shows two different devices using the proxy at the same time, each appearing as its own client on the dashboard. Client 1 is the computer running the proxy. Client 2 is a phone or a second laptop on the same Wi-Fi.

Only use this on a network you control. Some campus or guest Wi-Fi networks block devices from talking to each other. If the phone cannot reach your computer, use a phone hotspot or a home router instead.

### 1. Find the two addresses

- Proxy computer: run `ipconfig` and note the IPv4 address of your Wi-Fi or Ethernet adapter. Call it `PC_IP`.
- Second device: open its Wi-Fi settings and note its IP address. Call it `PHONE_IP`.

Both must be private addresses (for example `192.168.x.x`, `10.x.x.x` or `172.16-31.x.x`).

### 2. Allow the clients

Put both addresses in `config/allowed-lan-clients.txt`, one per line:

```
192.168.1.20
192.168.1.45
```

The proxy refuses to start on a network address with an empty list, and it answers `403` to any client not on it. If the phone's address is wrong, its requests are rejected silently and nothing appears on the dashboard.

### 3. Start the proxy on the LAN address

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run.ps1 --bind 192.168.1.20
```

```bash
bash scripts/run.sh --bind 192.168.1.20
```

Use your own `PC_IP`. Windows Firewall may ask whether Java can use the network. Allow it on private networks. Never bind to `0.0.0.0` or expose the port to the internet.

Then open `http://127.0.0.1:8181` on the proxy computer. The dashboard is not reachable from other devices on purpose.

For clean screenshots, stop the app first and delete `data/proxy-events.jsonl` before starting it again. The file is not tracked by git.

### 4. Client 1: send traffic from the proxy computer

```powershell
powershell -ExecutionPolicy Bypass -File scripts/demo-traffic.ps1 -Proxy 192.168.1.20
```

```bash
bash scripts/demo-traffic.sh 192.168.1.20
```

The script sends three requests and prints the status code for each:

| Request | Expected |
| --- | --- |
| `http://example.com/` | `200`, logged as `GET` with outcome `CONNECTED` |
| `https://example.org/` | `200`, logged as `CONNECT` (`HTTPS_TUNNEL`) with outcome `CONNECTED` |
| `http://169.254.169.254/` | `403`, logged with outcome `DENIED` |

It needs internet access, since the first two go to real sites.

### 5. Client 2: point the phone at the proxy

In the phone's Wi-Fi settings for this network, set the proxy to Manual, host `PC_IP`, port `8888`. Then browse to `http://example.com`, `http://neverssl.com` and `https://example.org`. A browser on the phone will also make some background requests, so expect a few extra rows.

### 6. What to look for on the dashboard

- Rows from both `PC_IP` and `PHONE_IP` in the table.
- Type `PHONE_IP` into Client IP to see only the phone's traffic.
- Type `example` into Domain to narrow by destination.
- Pick Last 5 minutes in Time range to hide older entries.
- The `DENIED` row from the blocked request.
- Type something that matches nothing to see the "Nothing matches these filters" message.

### 7. Clean up

Press Ctrl+C in the proxy window, turn the proxy off in the phone's Wi-Fi settings, and put the allowlist back so you do not commit your own IP addresses:

```bash
git checkout config/allowed-lan-clients.txt
```

If you set a system-wide proxy in Windows to use this one, turn it off too. Otherwise the computer loses internet access when the proxy stops.

## Dashboard API

All endpoints are read-only and answer on `127.0.0.1:8181`.

| Endpoint | Returns |
| --- | --- |
| `/api/events?client=&domain=&limit=` | Matching events as a JSON array, oldest first. `client` is an exact IP, `domain` is a case-insensitive substring, `limit` defaults to 100 and is capped at 500 |
| `/api/summary` | Counts of connected, failed and denied events among the retained ones |
| `/api/status` | `{"storage":"ok"}` or `{"storage":"error"}` depending on whether the log can be written |
| `/health` | `ok` |

The dashboard shows the latest 500 events. The time range filter works on those, in the browser.

## Repository layout

```
src/main/java/com/demo/netguard/   application code
src/test/java/com/demo/netguard/   the four test classes
scripts/                           build, run, test and demo-traffic (.ps1 and .sh)
config/allowed-lan-clients.txt     client allowlist for LAN mode
docs/examples/                     synthetic events used by EventLogTest
data/                              runtime log (not tracked)
```

## Limits

- Only `GET`, `HEAD` and `CONNECT`. Requests with a body, such as `POST`, are rejected.
- No TLS inspection, no authentication, no per-user identity. The client IP is the address the proxy saw, nothing more.
- Rotation keeps about 4 MiB of log history in total. Older records are discarded.
- If the log cannot be written, the dashboard shows a warning banner, but the proxy itself does not report it.
- Built for a lab. It has not been hardened for hostile networks.

Troubleshooting

- `ForwardProxyServerTest`
- A request does not appear on the dashboard. Check `NO_PROXY` (see above), that the client IP is on the allowlist in LAN mode, and that the client really uses port 8888.
- `scripts/test.sh` cannot find a class on Windows. Use `test.ps1`. The shell script uses a `:` classpath separator, which Windows Java does not accept.
