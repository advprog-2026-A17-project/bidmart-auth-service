package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record OAuthLoginRequest(
        @NotBlank(message = "Provider is required")
        String provider,
        @NotBlank(message = "Provider user id is required")
        String providerUserId,
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,
        @NotBlank(message = "Display name is required")
        String displayName
) {
}
