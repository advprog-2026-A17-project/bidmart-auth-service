package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;

import java.util.Set;
import java.util.UUID;

public record UserProfileResponse(
        UUID id,
        String email,
        boolean enabled,
        String displayName,
        String avatarUrl,
        String shippingAddress,
        Set<AuthUserResponse.RoleSummary> roles
) {
    public static UserProfileResponse fromUser(User user) {
        Set<AuthUserResponse.RoleSummary> roleSummaries = user.getRoles().stream()
                .map(AuthUserResponse.RoleSummary::fromRole)
                .collect(java.util.stream.Collectors.toSet());

        return new UserProfileResponse(
                user.getId(),
                user.getEmail(),
                user.isEnabled(),
                user.getDisplayName(),
                user.getAvatarUrl(),
                user.getShippingAddress(),
                roleSummaries
        );
    }
}
