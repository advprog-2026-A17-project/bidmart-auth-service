package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.dto.TokenResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.model.RefreshToken;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.RefreshTokenRepository;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
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

    @InjectMocks
    private TokenService tokenService;

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

        TokenResponse response = tokenService.issueTokens(user);

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

        TokenResponse response = tokenService.refreshTokens(tokenService.generateRefreshToken(user).refreshToken());

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

        tokenService.revokeRefreshToken(tokenService.generateRefreshToken(user).refreshToken());

        assertTrue(existing.isRevoked());
        verify(refreshTokenRepository).save(existing);
    }
}
