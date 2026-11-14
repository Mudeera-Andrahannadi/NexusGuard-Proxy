package com.demo.netguard.security;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Looks for well-known attack signatures in a request target and in the User-Agent header.
 * Stateless and thread-safe.
 *
 * <p>This is a short, readable signature list for a lab proxy, not a web application firewall.
 * It only sees what the proxy sees: for HTTPS tunnels that is the User-Agent and nothing else,
 * because the path travels inside the encrypted tunnel.
 */
public final class SignatureScanner {
    public enum Threat { NONE, DIRECTORY_TRAVERSAL, SQL_INJECTION, XSS, SCANNER_USER_AGENT }

    private static final int MAX_DECODE_ROUNDS = 3;
    private static final int CASE_INSENSITIVE = Pattern.CASE_INSENSITIVE;

    private static final Pattern TRAVERSAL = Pattern.compile("\\.\\.[/\\\\]|[/\\\\]\\.\\.$");

    private static final List<Pattern> SQL_INJECTION = List.of(
        // ' OR 1=1   'or'1'='1   " and "a"="a
        Pattern.compile("['\"]\\s*(or|and)\\s*['\"]?\\w+['\"]?\\s*=\\s*['\"]?\\w", CASE_INSENSITIVE),
        Pattern.compile("\\bunion[\\s/*]+(all[\\s/*]+)?select\\b", CASE_INSENSITIVE),
        Pattern.compile("\\b(drop|truncate)\\s+table\\b", CASE_INSENSITIVE),
        Pattern.compile("['\"]\\s*--", CASE_INSENSITIVE),
        Pattern.compile("\\b(sleep|benchmark)\\s*\\(|\\bwaitfor\\s+delay\\b", CASE_INSENSITIVE));

    private static final List<Pattern> XSS = List.of(
        Pattern.compile("<\\s*/?\\s*(script|iframe|object|embed)", CASE_INSENSITIVE),
        Pattern.compile("javascript\\s*:", CASE_INSENSITIVE),
        Pattern.compile("\\bon(error|load|click|mouseover|focus)\\s*=", CASE_INSENSITIVE),
        Pattern.compile("document\\.cookie", CASE_INSENSITIVE));

    private static final List<String> SCANNER_AGENTS = List.of(
        "nmap", "nikto", "sqlmap", "dirbuster", "gobuster", "masscan", "wpscan", "hydra", "acunetix", "nessus");

    /**
     * @param requestTarget the request-line target exactly as the client sent it
     * @param userAgent the User-Agent header value, or null when absent
     * @return the first threat found, or {@link Threat#NONE}
     */
    public Threat scan(String requestTarget, String userAgent) {
        if (userAgent != null) {
            String agent = userAgent.toLowerCase(Locale.ROOT);
            for (String scanner : SCANNER_AGENTS) if (agent.contains(scanner)) return Threat.SCANNER_USER_AGENT;
        }
        if (requestTarget == null) return Threat.NONE;
        String decoded = decodeFully(requestTarget);
        if (TRAVERSAL.matcher(decoded).find()) return Threat.DIRECTORY_TRAVERSAL;
        for (Pattern p : SQL_INJECTION) if (p.matcher(decoded).find()) return Threat.SQL_INJECTION;
        for (Pattern p : XSS) if (p.matcher(decoded).find()) return Threat.XSS;
        return Threat.NONE;
    }

    /** Decodes repeatedly so double and triple encoding cannot hide a signature. */
    private static String decodeFully(String text) {
        String current = text;
        for (int i = 0; i < MAX_DECODE_ROUNDS; i++) {
            String next = percentDecode(current);
            if (next.equals(current)) break;
            current = next;
        }
        return current;
    }

    /** Lenient on purpose: a bad escape such as %zz is kept as text instead of aborting the scan. */
    private static String percentDecode(String text) {
        byte[] out = new byte[text.length()];
        int n = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '%' && i + 2 < text.length() && hex(text.charAt(i + 1)) >= 0 && hex(text.charAt(i + 2)) >= 0) {
                out[n++] = (byte) (hex(text.charAt(i + 1)) * 16 + hex(text.charAt(i + 2)));
                i += 2;
            } else {
                out[n++] = c == '+' ? (byte) ' ' : c > 0xFF ? (byte) '?' : (byte) c;
            }
        }
        return new String(out, 0, n, StandardCharsets.ISO_8859_1);
    }

    private static int hex(char c) {
        return "0123456789abcdef".indexOf(Character.toLowerCase(c));
    }
}
