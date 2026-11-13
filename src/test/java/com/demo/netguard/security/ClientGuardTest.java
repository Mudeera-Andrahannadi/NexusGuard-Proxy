package com.demo.netguard.security;

import com.demo.netguard.monitor.EventLog;
import com.demo.netguard.proxy.ForwardProxyServer;
import com.demo.netguard.security.ClientGuard.Verdict;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Rate limiting and automatic blocking, on a fake clock and through a real proxy on loopback. */
public final class ClientGuardTest {
    private static int checks;

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
        checks++;
        System.out.println("  OK " + label);
    }

    private static String request(int port) throws IOException {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(5000);
            // A denied destination answers without any upstream connection, so no network is needed.
            socket.getOutputStream().write(
                "GET http://169.254.169.254/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            socket.shutdownOutput();
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    public static void main(String[] args) throws Exception {
        AtomicLong now = new AtomicLong(1_000);
        ClientGuard guard = new ClientGuard(3, 10_000, 60_000, now::get);

        check(guard.check("10.0.0.1") == Verdict.ALLOWED && guard.check("10.0.0.1") == Verdict.ALLOWED
                && guard.check("10.0.0.1") == Verdict.ALLOWED,
            "a client may use its whole allowance");
        check(guard.check("10.0.0.1") == Verdict.JUST_BLOCKED, "the first request over the limit blocks the client");
        check(guard.check("10.0.0.1") == Verdict.BLOCKED && guard.check("10.0.0.1") == Verdict.BLOCKED,
            "later requests are refused without announcing the block again");
        check(guard.check("10.0.0.2") == Verdict.ALLOWED, "another client is not affected");
        check(guard.blocked().equals(Map.of("10.0.0.1", 60_000L)), "blocked() lists only the blocked client and its time left");

        now.addAndGet(59_999);
        check(guard.check("10.0.0.1") == Verdict.BLOCKED, "the block holds until the block time has passed");
        check(guard.blocked().get("10.0.0.1") == 1L, "blocked() counts the time left down");
        now.addAndGet(1);
        check(guard.blocked().isEmpty(), "blocked() is empty once the block has run out");
        check(guard.check("10.0.0.1") == Verdict.ALLOWED, "the block lifts by itself");

        ClientGuard slow = new ClientGuard(3, 10_000, 60_000, now::get);
        for (int i = 0; i < 20; i++) {
            now.addAndGet(4_000);
            if (slow.check("10.0.0.3") != Verdict.ALLOWED) throw new AssertionError("steady slow client was blocked");
        }
        checks++;
        System.out.println("  OK a steady client under the limit is never blocked");

        ClientGuard burst = new ClientGuard(3, 10_000, 60_000, now::get);
        for (int i = 0; i < 3; i++) burst.check("10.0.0.4");
        now.addAndGet(10_000);
        check(burst.check("10.0.0.4") == Verdict.ALLOWED, "old requests fall out of the window");

        boolean rejected = false;
        try { new ClientGuard(0, 1, 1); } catch (IllegalArgumentException expected) { rejected = true; }
        check(rejected, "a limit of zero is rejected");

        ClientGuard shared = new ClientGuard(50, 60_000, 60_000);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        AtomicInteger announced = new AtomicInteger();
        try {
            java.util.List<Future<?>> jobs = new java.util.ArrayList<>();
            for (int i = 0; i < 400; i++)
                jobs.add(pool.submit(() -> { if (shared.check("10.0.0.5") == Verdict.JUST_BLOCKED) announced.incrementAndGet(); }));
            for (Future<?> job : jobs) job.get(10, TimeUnit.SECONDS);
        } finally { pool.shutdownNow(); }
        check(announced.get() == 1, "concurrent requests announce the block exactly once");

        Path dir = Files.createTempDirectory("client-guard-test-");
        Path file = dir.resolve("events.jsonl");
        EventLog log = new EventLog(file);
        try (ForwardProxyServer proxy = new ForwardProxyServer(0, "127.0.0.1", Set.of(), log, 1,
                new ClientGuard(3, 60_000, 60_000))) {
            proxy.start();
            for (int i = 1; i <= 3; i++)
                check(request(proxy.port()).startsWith("HTTP/1.1 403"), "request " + i + " within the limit is handled normally");
            String blocked = request(proxy.port());
            check(blocked.startsWith("HTTP/1.1 429") && blocked.contains("blocked for a while"),
                "request over the limit gets 429 Too Many Requests");
            check(request(proxy.port()).startsWith("HTTP/1.1 429"), "the client stays blocked");
        }
        String json = log.recentJson(100, "", "");
        check(json.split("RATE_LIMIT_EXCEEDED", -1).length == 2, "the block is logged exactly once");
        check(json.contains("\"outcome\":\"DENIED\"") && json.contains("\"sourceIp\":\"127.0.0.1\""),
            "the block event is a DENIED record for the client");
        check(new EventLog(file).recentJson(100, "", "").contains("RATE_LIMIT_EXCEEDED"),
            "the block event survives a restart");

        System.out.println("PASS: " + checks + " ClientGuard checks");
    }
}
