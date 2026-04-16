package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import jakarta.validation.constraints.NotBlank;

public record OAuthLoginRequest(
        @NotBlank(message = "Provider is required")
        String provider,
        @NotBlank(message = "Google ID token is required")
        String idToken
) {
}
