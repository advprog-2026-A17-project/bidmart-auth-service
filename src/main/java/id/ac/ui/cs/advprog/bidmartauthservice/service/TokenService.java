package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.dto.AuthUserResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.SessionResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.TokenResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.TwoFactorChallengeResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.InvalidRefreshTokenException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.InvalidTwoFactorChallengeException;
import id.ac.ui.cs.advprog.bidmartauthservice.model.RefreshToken;
import id.ac.ui.cs.advprog.bidmartauthservice.model.TwoFactorChallenge;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.RefreshTokenRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.TwoFactorChallengeRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class TokenService {

    private static final String TOKEN_TYPE_ACCESS = "access";
    private static final String TOKEN_TYPE_REFRESH = "refresh";
    private static final String TOKEN_TYPE_BEARER = "Bearer";
    private static final long TWO_FACTOR_CHALLENGE_TTL_SECONDS = 300L; // 5 minutes

    private final RefreshTokenRepository refreshTokenRepository;
    private final TwoFactorChallengeRepository twoFactorChallengeRepository;
    private final UserRepository userRepository;

    @Value("${app.auth.jwt.access-ttl-seconds:900}")
    private long accessTokenExpirySeconds;

    @Value("${app.auth.jwt.refresh-ttl-seconds:604800}")
    private long refreshTokenExpirySeconds;

    @Value("${app.auth.jwt.secret:bidmart-auth-secret-key-bidmart-auth-secret-key}")
    private String jwtSecret;

    public TokenService(
            RefreshTokenRepository refreshTokenRepository,
            TwoFactorChallengeRepository twoFactorChallengeRepository,
            UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.twoFactorChallengeRepository = twoFactorChallengeRepository;
        this.userRepository = userRepository;
    }

    public TokenResponse issueTokens(User user) {
        String accessToken = generateAccessToken(user);
        TokenResponse refreshOnlyResponse = generateRefreshToken(user);

        return new TokenResponse(
                accessToken,
                refreshOnlyResponse.refreshToken(),
                TOKEN_TYPE_BEARER,
                accessTokenExpirySeconds,
                AuthUserResponse.fromUser(user)
        );
    }

    public TwoFactorChallengeResponse issueTwoFactorChallenge(User user) {
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(UUID.randomUUID().toString().getBytes());
        String tokenHash = hashToken(rawToken);

        TwoFactorChallenge challenge = TwoFactorChallenge.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(Instant.now().plusSeconds(TWO_FACTOR_CHALLENGE_TTL_SECONDS))
                .used(false)
                .build();
        
        twoFactorChallengeRepository.save(challenge);
        return new TwoFactorChallengeResponse(rawToken);
    }

    public User verifyTwoFactorChallenge(String challengeToken) {
        String tokenHash = hashToken(challengeToken);
        TwoFactorChallenge challenge = twoFactorChallengeRepository.findByTokenHashAndUsedFalse(tokenHash)
                .orElseThrow(() -> new InvalidTwoFactorChallengeException("Invalid or expired 2FA challenge token"));

        if (challenge.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidTwoFactorChallengeException("2FA challenge token has expired");
        }

        challenge.setUsed(true);
        twoFactorChallengeRepository.save(challenge);

        return challenge.getUser();
    }

    public TokenResponse generateRefreshToken(User user) {
        UUID tokenId = UUID.randomUUID();
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(refreshTokenExpirySeconds);
        String refreshToken = Jwts.builder()
                .subject(user.getId().toString())
                .id(tokenId.toString())
                .claim("type", TOKEN_TYPE_REFRESH)
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiresAt))
                .signWith(getSigningKey())
                .compact();

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .id(UUID.randomUUID())
                .tokenId(tokenId)
                .user(user)
                .expiresAt(expiresAt)
                .revoked(false)
                .createdAt(issuedAt)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);

        return new TokenResponse(
                null,
                refreshToken,
                TOKEN_TYPE_BEARER,
                0L,
                AuthUserResponse.fromUser(user)
        );
    }

    public TokenResponse refreshTokens(String refreshToken) {
        Claims claims = parseAndValidateRefreshToken(refreshToken);
        UUID tokenId = UUID.fromString(claims.getId());

        RefreshToken refreshTokenEntity = refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        if (refreshTokenEntity.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidRefreshTokenException("Refresh token expired");
        }

        refreshTokenEntity.setRevoked(true);
        refreshTokenRepository.save(refreshTokenEntity);

        return issueTokens(refreshTokenEntity.getUser());
    }

    public void revokeRefreshToken(String refreshToken) {
        try {
            Claims claims = parseAndValidateRefreshToken(refreshToken);
            UUID tokenId = UUID.fromString(claims.getId());
            refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId).ifPresent(token -> {
                token.setRevoked(true);
                refreshTokenRepository.save(token);
            });
        } catch (RuntimeException ignored) {
            // idempotent revoke behavior
        }
    }

    public List<SessionResponse> listActiveSessions(String email) {
        return userRepository.findByEmail(email)
                .map(user -> refreshTokenRepository.findByUserIdAndRevokedFalse(user.getId()).stream()
                        .map(SessionResponse::fromRefreshToken)
                        .toList())
                .orElse(List.of());
    }

    public void revokeSessionByTokenId(UUID tokenId) {
        refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId).ifPresent(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
        });
    }

    public void revokeAllSessionsForUser(UUID userId) {
        List<RefreshToken> activeSessions = refreshTokenRepository.findByUserIdAndRevokedFalse(userId);
        for (RefreshToken session : activeSessions) {
            session.setRevoked(true);
            refreshTokenRepository.save(session);
        }
    }

    private String generateAccessToken(User user) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(accessTokenExpirySeconds);

        return Jwts.builder()
                .subject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("roles", user.getRoles().stream().map(role -> role.getName()).toList())
                .claim("type", TOKEN_TYPE_ACCESS)
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiresAt))
                .signWith(getSigningKey())
                .compact();
    }

    private Claims parseAndValidateRefreshToken(String refreshToken) {
        Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(refreshToken)
                .getPayload();

        if (!TOKEN_TYPE_REFRESH.equals(claims.get("type", String.class))) {
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }
        return claims;
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
