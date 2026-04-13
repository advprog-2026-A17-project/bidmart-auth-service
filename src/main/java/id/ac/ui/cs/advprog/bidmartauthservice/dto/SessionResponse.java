package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import id.ac.ui.cs.advprog.bidmartauthservice.model.RefreshToken;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

public record SessionResponse(
        UUID tokenId,
        String email,
        boolean revoked,
        String expiresAt
) {
    public static SessionResponse fromRefreshToken(RefreshToken refreshToken) {
        return new SessionResponse(
                refreshToken.getTokenId(),
                refreshToken.getUser().getEmail(),
                refreshToken.isRevoked(),
                DateTimeFormatter.ISO_INSTANT.format(refreshToken.getExpiresAt().atOffset(ZoneOffset.UTC))
        );
    }
}
