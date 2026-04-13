package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;

import java.util.Set;
import java.util.UUID;

public record AuthUserResponse(
        UUID id,
        String email,
        boolean enabled,
        Set<RoleSummary> roles
) {
    public static AuthUserResponse fromUser(User user) {
        Set<RoleSummary> roleSummaries = user.getRoles().stream()
                .map(role -> new RoleSummary(role.getId(), role.getName()))
                .collect(java.util.stream.Collectors.toSet());

        return new AuthUserResponse(
                user.getId(),
                user.getEmail(),
                user.isEnabled(),
                roleSummaries
        );
    }

    public record RoleSummary(UUID id, String name) {
        public static RoleSummary fromRole(Role role) {
            return new RoleSummary(role.getId(), role.getName());
        }
    }
}
