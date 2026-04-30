package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record TwoFactorLoginVerifyRequest(
        @NotBlank(message = "Challenge token is required")
        String challengeToken,
        @NotBlank(message = "TOTP code is required")
        @Pattern(regexp = "\\d{6}", message = "Code must be 6 digits")
        String code
) {
}
