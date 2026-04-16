package id.ac.ui.cs.advprog.bidmartauthservice.service.oauth;

public record OAuthIdentity(
        String subject,
        String email,
        String displayName,
        String avatarUrl
) {
}
