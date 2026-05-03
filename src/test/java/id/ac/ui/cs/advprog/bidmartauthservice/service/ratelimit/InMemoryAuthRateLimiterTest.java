package id.ac.ui.cs.advprog.bidmartauthservice.service.ratelimit;

import id.ac.ui.cs.advprog.bidmartauthservice.exception.RateLimitExceededException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("unit")
class InMemoryAuthRateLimiterTest {

    @Test
    void allowsAttemptsWithinConfiguredLimitAndNormalizesKey() {
        InMemoryAuthRateLimiter limiter = limiterAt(Instant.parse("2026-01-01T00:00:00Z"));

        assertDoesNotThrow(() -> limiter.assertAllowed(" LOGIN ", "USER@example.com"));
        assertDoesNotThrow(() -> limiter.assertAllowed("login", "user@example.com"));

        assertThrows(RateLimitExceededException.class, () -> limiter.assertAllowed("login", "user@example.com"));
    }

    @Test
    void separatesDifferentOperationsAndSubjects() {
        InMemoryAuthRateLimiter limiter = limiterAt(Instant.parse("2026-01-01T00:00:00Z"));

        assertDoesNotThrow(() -> limiter.assertAllowed("login", "user@example.com"));
        assertDoesNotThrow(() -> limiter.assertAllowed("refresh", "user@example.com"));
        assertDoesNotThrow(() -> limiter.assertAllowed("login", "other@example.com"));
    }

    @Test
    void resetsAttemptsAfterWindowExpires() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        InMemoryAuthRateLimiter limiter = new InMemoryAuthRateLimiter(clock);
        ReflectionTestUtils.setField(limiter, "maxAttempts", 1);
        ReflectionTestUtils.setField(limiter, "windowSeconds", 10L);

        limiter.assertAllowed("login", "user@example.com");
        assertThrows(RateLimitExceededException.class, () -> limiter.assertAllowed("login", "user@example.com"));

        clock.advanceSeconds(10);

        assertDoesNotThrow(() -> limiter.assertAllowed("login", "user@example.com"));
    }

    private InMemoryAuthRateLimiter limiterAt(Instant instant) {
        InMemoryAuthRateLimiter limiter = new InMemoryAuthRateLimiter(Clock.fixed(instant, ZoneOffset.UTC));
        ReflectionTestUtils.setField(limiter, "maxAttempts", 2);
        ReflectionTestUtils.setField(limiter, "windowSeconds", 60L);
        return limiter;
    }

    private static class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        private void advanceSeconds(long seconds) {
            instant = instant.plusSeconds(seconds);
        }
    }
}
