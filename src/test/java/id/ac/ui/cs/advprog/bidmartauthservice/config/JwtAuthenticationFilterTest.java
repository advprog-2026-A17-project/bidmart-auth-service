package id.ac.ui.cs.advprog.bidmartauthservice.config;

import id.ac.ui.cs.advprog.bidmartauthservice.model.RefreshToken;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.RefreshTokenRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.service.RedisSessionCacheService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@Tag("unit")
class JwtAuthenticationFilterTest {

    private static final String JWT_SECRET = "bidmart-auth-secret-key-bidmart-auth-secret-key";

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private RedisSessionCacheService redisSessionCacheService;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(filter, "jwtSecret", JWT_SECRET);
    }

    @Test
    void doFilterInternalShouldAllowActiveRedisSession() throws Exception {
        UUID tokenId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", bearerToken(tokenId, "buyer@test.com"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(redisSessionCacheService.isSessionActive(tokenId)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        assertEquals("123", request.getAttribute("userId"));
        assertEquals("buyer@test.com", request.getAttribute("userEmail"));
        assertEquals(200, response.getStatus());
        verify(filterChain).doFilter(request, response);
        verify(refreshTokenRepository, never()).findByTokenIdAndRevokedFalse(any());
    }

    @Test
    void doFilterInternalShouldFallBackToDatabaseWhenRedisMissOccurs() throws Exception {
        UUID tokenId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", bearerToken(tokenId, "buyer@test.com"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        RefreshToken activeToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .tokenId(tokenId)
                .expiresAt(Instant.now().plusSeconds(300))
                .revoked(false)
                .createdAt(Instant.now())
                .deviceInfo("Google Chrome")
                .build();

        when(redisSessionCacheService.isSessionActive(tokenId)).thenReturn(false);
        when(refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId)).thenReturn(Optional.of(activeToken));

        filter.doFilterInternal(request, response, filterChain);

        assertEquals("123", request.getAttribute("userId"));
        assertEquals("buyer@test.com", request.getAttribute("userEmail"));
        verify(refreshTokenRepository).findByTokenIdAndRevokedFalse(tokenId);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternalShouldRejectRevokedSessionWhenRedisAndDatabaseMiss() throws Exception {
        UUID tokenId = UUID.randomUUID();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", bearerToken(tokenId, "buyer@test.com"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(redisSessionCacheService.isSessionActive(tokenId)).thenReturn(false);
        when(refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId)).thenReturn(Optional.empty());

        filter.doFilterInternal(request, response, filterChain);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertEquals("Session has been revoked.", response.getErrorMessage());
        assertNull(request.getAttribute("userId"));
        assertNull(request.getAttribute("userEmail"));
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void doFilterInternalShouldIgnoreInvalidTokenAndContinueChain() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer not-a-jwt");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilterInternal(request, response, filterChain);

        assertFalse(response.isCommitted());
        assertNull(request.getAttribute("userId"));
        assertNull(request.getAttribute("userEmail"));
        verify(filterChain).doFilter(request, response);
    }

    private String bearerToken(UUID tokenId, String email) {
        return "Bearer " + Jwts.builder()
                .subject("123")
                .claim("email", email)
                .claim("type", "access")
                .claim("tokenId", tokenId.toString())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(300)))
                .signWith(Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }
}