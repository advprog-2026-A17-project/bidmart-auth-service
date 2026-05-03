package id.ac.ui.cs.advprog.bidmartauthservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Service for caching active session tokens in Redis.
 * Provides O(1) lookup validation for JWT tokens during authentication.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RedisSessionCacheService {

    private static final String SESSION_KEY_PREFIX = "session:";
    private final RedisTemplate<String, String> redisTemplate;

    @Value("${app.auth.jwt.refresh-ttl-seconds:604800}")
    private long refreshTokenExpirySeconds;

    /**
     * Cache a session token in Redis with TTL matching the refresh token expiry.
     * Called when a new session is created (login/refresh).
     */
    public void cacheSessionToken(UUID tokenId) {
        try {
            String key = buildSessionKey(tokenId);
            redisTemplate.opsForValue().set(key, "active", refreshTokenExpirySeconds, TimeUnit.SECONDS);
            log.debug("Cached session token: {}", tokenId);
        } catch (Exception e) {
            log.warn("Failed to cache session token: {}", tokenId, e);
            // Non-blocking: if Redis fails, JWT validation via DB still works
        }
    }

    /**
     * Check if a session token is still active in Redis.
     * Returns false if expired or revoked.
     */
    public boolean isSessionActive(UUID tokenId) {
        try {
            String key = buildSessionKey(tokenId);
            Boolean exists = redisTemplate.hasKey(key);
            return Boolean.TRUE.equals(exists);
        } catch (Exception e) {
            log.warn("Failed to check session status in Redis: {}", tokenId, e);
            // Fallback to DB validation in JwtAuthenticationFilter
            return true;
        }
    }

    /**
     * Invalidate (revoke) a session token by removing it from Redis.
     * Called when a session is revoked or user logs out.
     */
    public void revokeSessionToken(UUID tokenId) {
        try {
            String key = buildSessionKey(tokenId);
            redisTemplate.delete(key);
            log.debug("Revoked session token: {}", tokenId);
        } catch (Exception e) {
            log.warn("Failed to revoke session token: {}", tokenId, e);
        }
    }

    /**
     * Revoke all session tokens for a user.
     * Called when account is disabled or all sessions are revoked.
     */
    public void revokeUserSessions(java.util.Collection<UUID> tokenIds) {
        try {
            var keys = tokenIds.stream()
                    .map(this::buildSessionKey)
                    .toList();
            if (!keys.isEmpty()) {
                redisTemplate.delete(keys);
                log.debug("Revoked {} session tokens", keys.size());
            }
        } catch (Exception e) {
            log.warn("Failed to revoke user sessions", e);
        }
    }

    private String buildSessionKey(UUID tokenId) {
        return SESSION_KEY_PREFIX + tokenId;
    }
}
