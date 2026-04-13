package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record UpdateProfileRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        String email,
        @NotBlank(message = "Display name is required")
        String displayName,
        String avatarUrl,
        String shippingAddress
) {
}
