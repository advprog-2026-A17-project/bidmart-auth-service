package id.ac.ui.cs.advprog.bidmartauthservice.dto;

import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;

public record RoleResponse(
        UUID id,
        String name,
        List<String> permissions
) {
    public static RoleResponse fromRole(Role role) {
        List<String> permissionNames = role.getPermissions() == null
                ? List.of()
                : role.getPermissions().stream()
                        .map(permission -> permission.getName())
                        .sorted(Comparator.naturalOrder())
                        .toList();
        return new RoleResponse(role.getId(), role.getName(), permissionNames);
    }
}
