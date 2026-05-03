package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.dto.TokenResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.model.RefreshToken;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.TwoFactorChallenge;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.RefreshTokenRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.TwoFactorChallengeRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.UserRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.service.RedisSessionCacheService;
import id.ac.ui.cs.advprog.bidmartauthservice.service.SessionRevokePublisher;
import id.ac.ui.cs.advprog.bidmartauthservice.service.security.AuthAuditOutboxService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@Tag("unit")
class TokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private TwoFactorChallengeRepository twoFactorChallengeRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthAuditOutboxService authAuditOutboxService;

        @Mock
        private RedisSessionCacheService redisSessionCacheService;

        @Mock
        private SessionRevokePublisher sessionRevokePublisher;

    @InjectMocks
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(tokenService, "jwtSecret", "bidmart-auth-secret-key-bidmart-auth-secret-key");
        ReflectionTestUtils.setField(tokenService, "accessTokenExpirySeconds", 900L);
        ReflectionTestUtils.setField(tokenService, "refreshTokenExpirySeconds", 604800L);
    }

    @Test
    void issueTokensShouldPersistRefreshTokenAndReturnAccessToken() {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("token@test.com")
                .enabled(true)
                .roles(Set.of(Role.builder().id(UUID.randomUUID()).name("BUYER").build()))
                .build();

        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        TokenResponse response = tokenService.issueTokens(user, "Unit Test Browser");

        assertNotNull(response.accessToken());
        assertNotNull(response.refreshToken());
        assertEquals("Bearer", response.tokenType());
        assertEquals("token@test.com", response.user().email());
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void refreshTokensShouldRotateRefreshTokenWhenTokenValid() {
        UUID userId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .email("token@test.com")
                .enabled(true)
                .roles(Set.of(Role.builder().id(UUID.randomUUID()).name("BUYER").build()))
                .build();

        RefreshToken existing = RefreshToken.builder()
                .id(UUID.randomUUID())
                .tokenId(tokenId)
                .user(user)
                .expiresAt(Instant.now().plusSeconds(1800))
                .revoked(false)
                .build();

        when(refreshTokenRepository.findByTokenIdAndRevokedFalse(any(UUID.class)))
                .thenReturn(Optional.of(existing));
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        UUID refreshTokenId = UUID.randomUUID();
        TokenResponse response = tokenService.refreshTokens(
                tokenService.generateRefreshToken(user, "Unit Test Browser", refreshTokenId).refreshToken()
        );

        assertNotNull(response.accessToken());
        assertNotNull(response.refreshToken());
        assertTrue(existing.isRevoked());
        verify(refreshTokenRepository, atLeast(2)).save(any(RefreshToken.class));
    }

    @Test
    void revokeRefreshTokenShouldSetTokenRevoked() {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("token@test.com")
                .enabled(true)
                .roles(Set.of(Role.builder().id(UUID.randomUUID()).name("BUYER").build()))
                .build();
        UUID tokenId = UUID.randomUUID();
        RefreshToken existing = RefreshToken.builder()
                .id(UUID.randomUUID())
                .tokenId(tokenId)
                .user(user)
                .expiresAt(Instant.now().plusSeconds(1800))
                .revoked(false)
                .build();

        when(refreshTokenRepository.findByTokenIdAndRevokedFalse(any(UUID.class)))
                .thenReturn(Optional.of(existing));

        tokenService.revokeRefreshToken(
                tokenService.generateRefreshToken(user, "Unit Test Browser", UUID.randomUUID()).refreshToken()
        );

        assertTrue(existing.isRevoked());
        verify(refreshTokenRepository).save(existing);
    }

    @Test
    void listActiveSessionsShouldReturnUserSessionsByEmail() {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("token@test.com")
                .enabled(true)
                .roles(Set.of(Role.builder().id(UUID.randomUUID()).name("BUYER").build()))
                .build();
        RefreshToken activeSession = RefreshToken.builder()
                .id(UUID.randomUUID())
                .tokenId(UUID.randomUUID())
                .user(user)
                .expiresAt(Instant.now().plusSeconds(1800))
                .revoked(false)
                .createdAt(Instant.now().minusSeconds(30))
                .deviceInfo("Unit Test Browser")
                .build();

        when(userRepository.findByEmail("token@test.com")).thenReturn(Optional.of(user));
        when(refreshTokenRepository.findByUserIdAndRevokedFalse(user.getId()))
                .thenReturn(List.of(activeSession));

        assertEquals(1, tokenService.listActiveSessions("token@test.com").size());
    }

    @Test
    void revokeSessionByTokenIdShouldRevokeSessionWhenExists() {
        UUID tokenId = UUID.randomUUID();
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("token@test.com")
                .enabled(true)
                .roles(Set.of(Role.builder().id(UUID.randomUUID()).name("BUYER").build()))
                .build();
        RefreshToken session = RefreshToken.builder()
                .id(UUID.randomUUID())
                .tokenId(tokenId)
                .user(user)
                .expiresAt(Instant.now().plusSeconds(1800))
                .revoked(false)
                .build();

        when(refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId)).thenReturn(Optional.of(session));

        tokenService.revokeSessionByTokenId(tokenId);

        assertTrue(session.isRevoked());
        verify(refreshTokenRepository).save(session);
        verify(authAuditOutboxService).enqueueSessionRevoked(session);
    }

    @Test
    void issueTwoFactorChallengeShouldPersistChallengeAndReturnRawToken() {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("token@test.com")
                .enabled(true)
                .roles(Set.of(Role.builder().id(UUID.randomUUID()).name("BUYER").build()))
                .build();

        when(twoFactorChallengeRepository.save(any(TwoFactorChallenge.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        var response = tokenService.issueTwoFactorChallenge(user);

        assertNotNull(response.challengeToken());
        assertTrue(response.twoFactorRequired());
        assertEquals("Two-factor authentication required", response.message());
        verify(twoFactorChallengeRepository).save(argThat(challenge ->
                challenge.getUser().equals(user)
                        && !challenge.isUsed()
                        && challenge.getTokenHash() != null
                        && challenge.getExpiresAt().isAfter(Instant.now())
        ));
    }

    @Test
    void verifyTwoFactorChallengeShouldMarkChallengeUsedAndReturnUser() {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("token@test.com")
                .enabled(true)
                .roles(Set.of(Role.builder().id(UUID.randomUUID()).name("BUYER").build()))
                .build();
        var challengeResponse = tokenService.issueTwoFactorChallenge(user);
        TwoFactorChallenge savedChallenge = mockingDetails(twoFactorChallengeRepository)
                .getInvocations()
                .stream()
                .filter(invocation -> invocation.getMethod().getName().equals("save"))
                .map(invocation -> (TwoFactorChallenge) invocation.getArgument(0))
                .findFirst()
                .orElseThrow();

        when(twoFactorChallengeRepository.findByTokenHashAndUsedFalse(savedChallenge.getTokenHash()))
                .thenReturn(Optional.of(savedChallenge));

        User verifiedUser = tokenService.verifyTwoFactorChallenge(challengeResponse.challengeToken());

        assertEquals(user, verifiedUser);
        assertTrue(savedChallenge.isUsed());
        verify(twoFactorChallengeRepository, times(2)).save(savedChallenge);
    }

    @Test
    void generateRefreshTokenShouldRevokeOldestSessionWhenLimitReached() {
        ReflectionTestUtils.setField(tokenService, "maxConcurrentSessions", 2);
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("token@test.com")
                .enabled(true)
                .roles(Set.of(Role.builder().id(UUID.randomUUID()).name("BUYER").build()))
                .build();
        RefreshToken oldestSession = RefreshToken.builder()
                .id(UUID.randomUUID())
                .tokenId(UUID.randomUUID())
                .user(user)
                .expiresAt(Instant.now().plusSeconds(1800))
                .revoked(false)
                .createdAt(Instant.now().minusSeconds(120))
                .build();
        RefreshToken newestSession = RefreshToken.builder()
                .id(UUID.randomUUID())
                .tokenId(UUID.randomUUID())
                .user(user)
                .expiresAt(Instant.now().plusSeconds(1800))
                .revoked(false)
                .createdAt(Instant.now().minusSeconds(60))
                .build();

        when(refreshTokenRepository.findByUserIdAndRevokedFalse(user.getId()))
                .thenReturn(List.of(newestSession, oldestSession));
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        TokenResponse response = tokenService.generateRefreshToken(user, "Unit Test Browser", UUID.randomUUID());

        assertNotNull(response.refreshToken());
        assertTrue(oldestSession.isRevoked());
        assertFalse(newestSession.isRevoked());
        verify(refreshTokenRepository).save(oldestSession);
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
    }
}
