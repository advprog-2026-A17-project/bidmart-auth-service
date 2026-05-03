package id.ac.ui.cs.advprog.bidmartauthservice.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisSessionCacheServiceTest {

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private RedisSessionCacheService redisSessionCacheService;

    private final UUID testTokenId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(redisSessionCacheService, "refreshTokenExpirySeconds", 604800L);
    }

    @Test
    void testCacheSessionToken_Success() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        redisSessionCacheService.cacheSessionToken(testTokenId);

        verify(valueOperations, times(1)).set("session:" + testTokenId, "active", 604800L, TimeUnit.SECONDS);
    }

    @Test
    void testCacheSessionToken_ExceptionCaught() {
        when(redisTemplate.opsForValue()).thenThrow(new RuntimeException("Redis down"));

        assertDoesNotThrow(() -> redisSessionCacheService.cacheSessionToken(testTokenId));
    }

    @Test
    void testIsSessionActive_Exists() {
        when(redisTemplate.hasKey("session:" + testTokenId)).thenReturn(true);

        boolean result = redisSessionCacheService.isSessionActive(testTokenId);

        assertTrue(result);
    }

    @Test
    void testIsSessionActive_DoesNotExist() {
        when(redisTemplate.hasKey("session:" + testTokenId)).thenReturn(false);

        boolean result = redisSessionCacheService.isSessionActive(testTokenId);

        assertFalse(result);
    }

    @Test
    void testIsSessionActive_ExceptionCaught_FallbackTrue() {
        when(redisTemplate.hasKey(anyString())).thenThrow(new RuntimeException("Redis down"));

        boolean result = redisSessionCacheService.isSessionActive(testTokenId);

        assertTrue(result);
    }

    @Test
    void testRevokeSessionToken_Success() {
        redisSessionCacheService.revokeSessionToken(testTokenId);

        verify(redisTemplate, times(1)).delete("session:" + testTokenId);
    }

    @Test
    void testRevokeSessionToken_ExceptionCaught() {
        doThrow(new RuntimeException("Redis down")).when(redisTemplate).delete(anyString());

        assertDoesNotThrow(() -> redisSessionCacheService.revokeSessionToken(testTokenId));
    }

    @Test
    void testRevokeUserSessions_EmptyList() {
        redisSessionCacheService.revokeUserSessions(Collections.emptyList());

        verify(redisTemplate, never()).delete(anyCollection());
    }

    @Test
    void testRevokeUserSessions_Success() {
        UUID token2 = UUID.randomUUID();
        List<UUID> tokens = List.of(testTokenId, token2);

        redisSessionCacheService.revokeUserSessions(tokens);

        verify(redisTemplate, times(1)).delete(List.of("session:" + testTokenId, "session:" + token2));
    }

    @Test
    void testRevokeUserSessions_ExceptionCaught() {
        doThrow(new RuntimeException("Redis down")).when(redisTemplate).delete(anyCollection());

        assertDoesNotThrow(() -> redisSessionCacheService.revokeUserSessions(List.of(testTokenId)));
    }
}