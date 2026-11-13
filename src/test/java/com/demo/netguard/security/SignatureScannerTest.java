package com.demo.netguard.security;

import com.demo.netguard.monitor.EventLog;
import com.demo.netguard.proxy.ForwardProxyServer;
import com.demo.netguard.security.SignatureScanner.Threat;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

/** Attack signatures, evasion attempts, false positives, and the scanner inside a real proxy. */
public final class SignatureScannerTest {
    private static int checks;
    private static final SignatureScanner SCANNER = new SignatureScanner();

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
        checks++;
        System.out.println("  OK " + label);
    }

    private static void expect(Threat expected, String target, String agent) {
        Threat actual = SCANNER.scan(target, agent);
        if (actual != expected)
            throw new AssertionError("expected " + expected + " but got " + actual + " for " + target + " / " + agent);
    }

    private static void allExpect(Threat expected, String label, String... targets) {
        for (String target : targets) expect(expected, target, null);
        checks++;
        System.out.println("  OK " + label);
    }

    private static String request(int port, String requestLine, String... headers) throws IOException {
        StringBuilder message = new StringBuilder(requestLine).append("\r\n");
        for (String header : headers) message.append(header).append("\r\n");
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(5000);
            socket.getOutputStream().write(message.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1));
            socket.shutdownOutput();
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    public static void main(String[] args) throws Exception {
        allExpect(Threat.DIRECTORY_TRAVERSAL, "directory traversal is found, plain and encoded",
            "http://h/../../etc/passwd", "http://h/..\\..\\windows\\win.ini", "http://h/a/%2e%2e/%2e%2e/b",
            "http://h/%2E%2E%5Cwindows", "http://h/%252e%252e%252fetc", "http://h/files/..", "http://h/..%2f%zz");
        allExpect(Threat.SQL_INJECTION, "SQL injection is found, plain and encoded",
            "http://h/?id=1' OR 1=1", "http://h/?id=1'+or+1%3D1--", "http://h/?u=%27%20Or%20%271%27%3D%271",
            "http://h/?q=1 UNION SELECT user,pass FROM t", "http://h/?q=1+union/**/select+1", "http://h/?q=x'--",
            "http://h/?q=1;DROP TABLE users", "http://h/?q=1 AND sleep(5)");
        allExpect(Threat.XSS, "cross-site scripting is found, plain and encoded",
            "http://h/?q=<script>alert(1)</script>", "http://h/?q=%3Cscript%3E", "http://h/?q=%3CSCRIPT%3E",
            "http://h/?q=javascript:alert(1)", "http://h/?q=<img src=x onerror=alert(1)>", "http://h/?c=document.cookie");

        expect(Threat.SCANNER_USER_AGENT, "http://h/", "Nmap Scripting Engine");
        expect(Threat.SCANNER_USER_AGENT, "http://h/", "Mozilla/5.00 (Nikto/2.1.5)");
        expect(Threat.SCANNER_USER_AGENT, "http://h/", "sqlmap/1.7.2#stable");
        expect(Threat.SCANNER_USER_AGENT, "http://h/", "DirBuster-1.0-RC1");
        checks++;
        System.out.println("  OK scanner User-Agents are found whatever the case");

        allExpect(Threat.NONE, "ordinary requests are left alone",
            "http://example.com/", "http://example.com/search?q=hello+world&page=2", "http://example.com/a..b/c",
            "http://example.com/online=1&once=2", "http://example.com/img/photo.jpg?w=100&h=50",
            "http://example.com/?q=it%27s+a+union+of+two+selected+teams", "http://example.com/blog/2026/11/post.html",
            "example.com:443");
        expect(Threat.NONE, "http://example.com/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0");
        expect(Threat.NONE, "http://example.com/", null);
        expect(Threat.NONE, null, null);
        checks++;
        System.out.println("  OK normal browsers, a missing User-Agent and a missing target are left alone");

        String hostile = "'" + " ".repeat(4000) + "%".repeat(4000);
        long start = System.nanoTime();
        for (int i = 0; i < 20; i++) SCANNER.scan("http://h/?q=" + hostile, "x");
        check((System.nanoTime() - start) / 1_000_000 < 2000, "an 8 KiB hostile target is scanned quickly");

        Path dir = Files.createTempDirectory("signature-scanner-test-");
        Path file = dir.resolve("events.jsonl");
        EventLog log = new EventLog(file);
        String host = "169.254.169.254"; // refused by policy before any connection, so no network is needed
        try (ForwardProxyServer proxy = new ForwardProxyServer(0, "127.0.0.1", Set.of(), log, 1, null, SCANNER);
             ForwardProxyServer plain = new ForwardProxyServer(0, "127.0.0.1", Set.of(), log, 1)) {
            proxy.start();
            plain.start();
            String hostHeader = "Host: " + host;

            String clean = request(proxy.port(), "GET http://" + host + "/ HTTP/1.1", hostHeader);
            check(clean.startsWith("HTTP/1.1 403") && clean.contains("Destination not permitted"),
                "a clean request still reaches the normal checks");
            String traversal = request(proxy.port(), "GET http://" + host + "/../../etc/passwd HTTP/1.1", hostHeader);
            check(traversal.startsWith("HTTP/1.1 403") && traversal.contains("suspicious pattern"),
                "directory traversal is refused with 403");
            String raw = request(proxy.port(), "GET http://example.com/?q=<script>alert(1)</script> HTTP/1.1", "Host: example.com");
            check(raw.startsWith("HTTP/1.1 403") && raw.contains("suspicious pattern"),
                "an unencoded attack the URL parser would reject is still caught and refused");
            String agent = request(proxy.port(), "GET http://" + host + "/ HTTP/1.1", hostHeader, "User-Agent: sqlmap/1.7");
            check(agent.contains("suspicious pattern"), "a scanner User-Agent is refused");
            String tunnel = request(proxy.port(), "CONNECT example.com:443 HTTP/1.1", "Host: example.com:443", "User-Agent: Nikto/2.1");
            check(tunnel.contains("suspicious pattern"), "a scanner User-Agent is refused on a CONNECT tunnel too");
            String sql = request(proxy.port(), "GET http://" + host + "/?id=1%27%20or%201%3D1 HTTP/1.1", hostHeader);
            check(sql.contains("suspicious pattern"), "encoded SQL injection is refused");

            String unscanned = request(plain.port(), "GET http://" + host + "/../../etc/passwd HTTP/1.1", hostHeader);
            check(unscanned.contains("Destination not permitted"), "without a scanner nothing changes");
        }
        String json = log.recentJson(100, "", "");
        check(json.contains("MALICIOUS_PATTERN_DETECTED:DIRECTORY_TRAVERSAL")
                && json.contains("MALICIOUS_PATTERN_DETECTED:XSS")
                && json.contains("MALICIOUS_PATTERN_DETECTED:SCANNER_USER_AGENT")
                && json.contains("MALICIOUS_PATTERN_DETECTED:SQL_INJECTION"),
            "each refusal is logged with its threat as the reason");
        check(json.split("MALICIOUS_PATTERN_DETECTED", -1).length == 6, "one log record per refused request");
        check(json.contains("\"outcome\":\"DENIED\"") && json.contains("\"destination\":\"" + host + "\""),
            "refusals are DENIED records that name the destination when it can be read");
        String text = Files.readString(file);
        check(!text.contains("passwd") && !text.contains("alert") && !text.contains("sqlmap") && !text.contains("onerror"),
            "the matched text is never written to the log");

        System.out.println("PASS: " + checks + " SignatureScanner checks");
    }
}
