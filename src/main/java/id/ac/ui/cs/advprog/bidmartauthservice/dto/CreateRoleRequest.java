package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record CreateRoleRequest(
        @NotBlank String name,
        @NotNull List<@NotBlank String> permissions
) {
}
