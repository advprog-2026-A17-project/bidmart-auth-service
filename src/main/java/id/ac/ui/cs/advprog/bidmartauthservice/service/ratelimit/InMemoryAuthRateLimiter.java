package id.ac.ui.cs.advprog.bidmartauthservice.service.ratelimit;

import id.ac.ui.cs.advprog.bidmartauthservice.exception.RateLimitExceededException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
public class InMemoryAuthRateLimiter implements AuthRateLimiter {

    private final ConcurrentMap<String, AttemptWindow> attempts = new ConcurrentHashMap<>();
    private final Clock clock;

    @Value("${app.auth.rate-limit.max-attempts:5}")
    private int maxAttempts;

    @Value("${app.auth.rate-limit.window-seconds:60}")
    private long windowSeconds;

    public InMemoryAuthRateLimiter() {
        this(Clock.systemUTC());
    }

    InMemoryAuthRateLimiter(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void assertAllowed(String operation, String subject) {
        String key = buildKey(operation, subject);
        Instant now = clock.instant();
        AttemptWindow window = attempts.compute(key, (ignored, existing) -> {
            if (existing == null || existing.expiresAt().isBefore(now) || existing.expiresAt().equals(now)) {
                return new AttemptWindow(1, now.plusSeconds(windowSeconds));
            }
            return new AttemptWindow(existing.count() + 1, existing.expiresAt());
        });

        if (window.count() > maxAttempts) {
            throw new RateLimitExceededException("Too many authentication attempts");
        }
    }

    private String buildKey(String operation, String subject) {
        return normalize(operation) + ":" + normalize(subject);
    }

    private String normalize(String value) {
        return Objects.toString(value, "anonymous").trim().toLowerCase(Locale.ROOT);
    }

    private record AttemptWindow(int count, Instant expiresAt) {
    }
}
