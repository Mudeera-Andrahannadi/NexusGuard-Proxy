package com.demo.netguard.security;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Per-client rate limit with automatic, temporary blocking. Thread-safe.
 *
 * <p>A client may open {@code maxRequests} connections in any {@code windowMillis} span.
 * The next one blocks that client for {@code blockMillis}; blocks lift on their own.
 * State is per source IP and only grows with the number of distinct clients, which the
 * proxy's allowlist already bounds.
 */
public final class ClientGuard {
    /** Result of one {@link #check}. */
    public enum Verdict {
        ALLOWED,
        /** This request pushed the client over the limit; report the block once. */
        JUST_BLOCKED,
        /** The client is already blocked; refuse quietly. */
        BLOCKED
    }

    private static final class Entry {
        final Deque<Long> hits = new ArrayDeque<>();
        long blockedUntil;
    }

    private final int maxRequests;
    private final long windowMillis;
    private final long blockMillis;
    private final LongSupplier clockMillis;
    private final Map<String, Entry> clients = new HashMap<>();

    public ClientGuard(int maxRequests, long windowMillis, long blockMillis) {
        this(maxRequests, windowMillis, blockMillis, () -> System.nanoTime() / 1_000_000);
    }

    /** The clock is injectable so tests do not have to sleep. */
    ClientGuard(int maxRequests, long windowMillis, long blockMillis, LongSupplier clockMillis) {
        if (maxRequests < 1 || windowMillis < 1 || blockMillis < 1)
            throw new IllegalArgumentException("Limit, window and block time must all be positive");
        this.maxRequests = maxRequests;
        this.windowMillis = windowMillis;
        this.blockMillis = blockMillis;
        this.clockMillis = clockMillis;
    }

    public synchronized Verdict check(String clientIp) {
        long now = clockMillis.getAsLong();
        Entry entry = clients.computeIfAbsent(clientIp, ip -> new Entry());
        if (now < entry.blockedUntil) return Verdict.BLOCKED;
        while (!entry.hits.isEmpty() && now - entry.hits.peekFirst() >= windowMillis) entry.hits.pollFirst();
        entry.hits.addLast(now);
        if (entry.hits.size() <= maxRequests) return Verdict.ALLOWED;
        entry.hits.clear();
        entry.blockedUntil = now + blockMillis;
        return Verdict.JUST_BLOCKED;
    }
}
