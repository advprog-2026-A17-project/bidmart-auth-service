package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record TwoFactorEmailRequest(
        @NotBlank @Email String email
) {
}
