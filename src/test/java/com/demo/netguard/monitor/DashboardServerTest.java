package com.demo.netguard.monitor;

import com.demo.netguard.model.FlowEvent;
import com.demo.netguard.security.ClientGuard;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

/**
 * Dashboard HTTP behaviour: filter parsing, storage status, page contract.
 * The browser-side time-range logic is plain JavaScript and is checked by hand in a browser.
 */
public final class DashboardServerTest {
    private static int checks;

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
        checks++;
        System.out.println("  OK " + label);
    }

    private static HttpResponse<String> get(HttpClient client, DashboardServer dashboard, String path) throws Exception {
        URI uri = URI.create("http://127.0.0.1:" + dashboard.port() + path);
        return client.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static FlowEvent event(String ip, String host, String outcome) {
        return new FlowEvent(Instant.parse("2026-11-12T10:00:00Z"), ip, "CONNECT", host, 443, "HTTPS_TUNNEL", outcome, "TEST");
    }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("dashboard-test-");
        Path file = directory.resolve("events.jsonl");
        EventLog log = new EventLog(file);
        log.append(event("192.168.1.10", "Example.com", "CONNECTED"));
        log.append(event("192.168.1.11", "other.org", "FAILED"));
        HttpClient http = HttpClient.newHttpClient();
        try (DashboardServer dashboard = new DashboardServer(0, log)) {
            dashboard.start();

            String events = get(http, dashboard, "/api/events?client=192.168.1.10&domain=EXAMPLE%2Ecom").body();
            check(events.contains("Example.com") && !events.contains("other.org"),
                "client and url-encoded domain filters combine");
            check(get(http, dashboard, "/api/events?client=nobody").body().equals("[]"),
                "filter with no match returns an empty array, not an error");

            HttpResponse<String> badLimit = get(http, dashboard, "/api/events?limit=abc");
            check(badLimit.statusCode() == 200 && badLimit.body().contains("other.org"),
                "non-numeric limit falls back to the default");
            HttpResponse<String> hugeQuery = get(http, dashboard, "/api/events?domain=" + "a".repeat(2000));
            check(hugeQuery.statusCode() == 200 && hugeQuery.body().contains("other.org"),
                "oversized query string is ignored instead of failing the request");

            HttpResponse<String> status = get(http, dashboard, "/api/status");
            check(status.body().equals("{\"storage\":\"ok\"}"), "status reports storage ok for a writable log");
            Files.delete(file);
            Files.createDirectory(file);
            check(get(http, dashboard, "/api/status").body().equals("{\"storage\":\"error\"}"),
                "status reports an error when the log path is a directory");
            check(get(http, dashboard, "/api/events").statusCode() == 200
                    && get(http, dashboard, "/api/summary").body().contains("\"recentTotal\":2"),
                "reads keep working from memory while storage is broken");
            Files.delete(file);
            check(get(http, dashboard, "/api/status").body().equals("{\"storage\":\"ok\"}"),
                "status recovers once the log can be created again");

            check(get(http, dashboard, "/health").body().equals("ok"), "health endpoint answers ok");
            check(get(http, dashboard, "/api/blocked").body().equals("[]"), "blocked list is empty when rate limiting is off");
            HttpResponse<String> page = get(http, dashboard, "/");
            check(page.headers().firstValue("Cache-Control").orElse("").equals("no-store")
                    && page.headers().firstValue("Content-Security-Policy").orElse("").contains("default-src 'self'"),
                "dashboard page is served with no-store and a content security policy");
            String html = page.body();
            check(html.contains("id=\"client\"") && html.contains("id=\"domain\"") && html.contains("id=\"range\"")
                    && html.contains("value=\"5\"") && html.contains("value=\"60\"") && html.contains("value=\"1440\""),
                "page has client, domain and time range controls with 5 min, 1 h and 24 h options");
            check(html.contains("Waiting for the first connection.")
                    && html.contains("Nothing matches these filters.")
                    && html.contains("No events in this time range.")
                    && html.contains("Can't write to the event log")
                    && html.contains("Can't reach the dashboard server."),
                "page carries the empty-state and error messages");
            check(html.contains("$('client').value.trim()") && html.contains("$('domain').value.trim()"),
                "page trims filter text so a stray space does not hide every event");
            check(html.contains("id=\"alert\"") && html.contains("Threats blocked") && html.contains("Clients blocked now")
                    && html.contains("Most common threat") && html.contains("Recent alerts") && html.contains("id=\"clients\""),
                "page has the alert banner, summary tiles, clients panel and recent alerts");
            check(html.contains("'/api/blocked'") && html.contains("dataset.until"),
                "page reads the blocked list and counts the block time down");
            check(html.contains("MALICIOUS_PATTERN_DETECTED:") && html.contains("RATE_LIMIT_EXCEEDED")
                    && html.contains("Blocked · ") && html.contains("Denied · ") && html.contains("id=\"show\""),
                "page tells threats from policy denials and can filter by them");
            check(!html.contains("innerHTML"), "page never builds the table with innerHTML");
        }
        ClientGuard guard = new ClientGuard(1, 60_000, 90_000);
        try (DashboardServer dashboard = new DashboardServer(0, log, guard)) {
            dashboard.start();
            check(get(http, dashboard, "/api/blocked").body().equals("[]"), "blocked list is empty while nobody is blocked");
            guard.check("192.168.1.45");
            guard.check("192.168.1.45");
            String blocked = get(http, dashboard, "/api/blocked").body();
            check(blocked.startsWith("[{\"ip\":\"192.168.1.45\",\"remainingSeconds\":") && blocked.endsWith("}]"),
                "blocked list names the blocked client");
            String key = "\"remainingSeconds\":";
            int seconds = Integer.parseInt(blocked.substring(blocked.indexOf(key) + key.length(), blocked.indexOf('}')));
            check(seconds > 85 && seconds <= 90, "blocked list reports the whole seconds left");
        }
        System.out.println("PASS: " + checks + " DashboardServer checks");
    }
}
