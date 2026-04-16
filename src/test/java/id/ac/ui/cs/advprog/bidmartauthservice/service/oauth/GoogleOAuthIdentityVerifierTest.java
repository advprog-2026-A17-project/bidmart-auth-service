package id.ac.ui.cs.advprog.bidmartauthservice.service.oauth;

import id.ac.ui.cs.advprog.bidmartauthservice.exception.InvalidOAuthTokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@Tag("unit")
class GoogleOAuthIdentityVerifierTest {

    @Mock
    private RestOperations restOperations;

    private GoogleOAuthIdentityVerifier verifier;

    @BeforeEach
    void setUp() {
        verifier = new GoogleOAuthIdentityVerifier(restOperations, "google-client-id");
    }

    @Test
    void verifyShouldReturnIdentityForValidToken() {
        when(restOperations.getForObject(
                "https://oauth2.googleapis.com/tokeninfo?id_token={idToken}",
                Map.class,
                "valid-id-token"
        )).thenReturn(Map.of(
                "aud", "google-client-id",
                "sub", "google-user-1",
                "email", "oauth@test.com",
                "email_verified", "true",
                "name", "OAuth User",
                "picture", "https://cdn.example.com/oauth-avatar.png"
        ));

        OAuthIdentity identity = verifier.verify("valid-id-token");

        assertEquals("google-user-1", identity.subject());
        assertEquals("oauth@test.com", identity.email());
        assertEquals("OAuth User", identity.displayName());
        assertEquals("https://cdn.example.com/oauth-avatar.png", identity.avatarUrl());
    }

    @Test
    void verifyShouldThrowWhenAudienceMismatch() {
        when(restOperations.getForObject(
                "https://oauth2.googleapis.com/tokeninfo?id_token={idToken}",
                Map.class,
                "valid-id-token"
        )).thenReturn(Map.of(
                "aud", "other-client-id",
                "sub", "google-user-1",
                "email", "oauth@test.com",
                "email_verified", "true"
        ));

        InvalidOAuthTokenException exception = assertThrows(
                InvalidOAuthTokenException.class,
                () -> verifier.verify("valid-id-token")
        );

        assertEquals("Google token audience mismatch", exception.getMessage());
    }

    @Test
    void verifyShouldThrowWhenGoogleReturnsInvalidTokenResponse() {
        when(restOperations.getForObject(
                "https://oauth2.googleapis.com/tokeninfo?id_token={idToken}",
                Map.class,
                "invalid-id-token"
        )).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));

        InvalidOAuthTokenException exception = assertThrows(
                InvalidOAuthTokenException.class,
                () -> verifier.verify("invalid-id-token")
        );

        assertEquals("Invalid Google ID token", exception.getMessage());
    }
}
