package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import jakarta.validation.constraints.NotBlank;

public record AssignRoleRequest(
        @NotBlank String role
) {
}
