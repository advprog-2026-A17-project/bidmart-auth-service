package id.ac.ui.cs.advprog.bidmartauthservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.LoginRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.RefreshTokenRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.RegisterRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.ResendVerificationRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.SessionResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.TokenResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.OAuthLoginRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.UpdateProfileRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.VerifyEmailRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.RoleNotFoundException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.EmailNotVerifiedException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.InvalidOAuthTokenException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.UnsupportedOAuthProviderException;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Permission;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.service.TokenService;
import id.ac.ui.cs.advprog.bidmartauthservice.service.AuthService;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.List;

import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Tag("unit")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private TokenService tokenService;

        @Autowired
        private ObjectMapper objectMapper;

    @Test
    void registerShouldReturnRegisteredUser() throws Exception {
        Role buyerRole = Role.builder()
                .id(UUID.randomUUID())
                .name("BUYER")
                .build();

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("controller@test.com");
        user.setPassword("pass");
        user.setEnabled(true);
        user.setRoles(Set.of(buyerRole));

        when(authService.register("controller@test.com", "pass", "BUYER"))
                .thenReturn(user);

        RegisterRequest request = new RegisterRequest("controller@test.com", "pass", "BUYER");

        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("controller@test.com"))
                .andExpect(jsonPath("$.roles[0].name").value("BUYER"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void loginShouldReturnUserWhenCredentialsValid() throws Exception {
        Role buyerRole = Role.builder()
                .id(UUID.randomUUID())
                .name("BUYER")
                .build();

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("buyer@test.com");
        user.setPassword("pass");
        user.setEnabled(true);
        user.setRoles(Set.of(buyerRole));

        when(authService.login("buyer@test.com", "pass"))
                .thenReturn(Optional.of(user));
        when(tokenService.issueTokens(user)).thenReturn(new TokenResponse(
                "access-token",
                "refresh-token",
                "Bearer",
                900,
                null
        ));

        LoginRequest request = new LoginRequest("buyer@test.com", "pass");

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.user.password").doesNotExist());
    }

    @Test
    void loginShouldReturnUnauthorizedWhenCredentialsInvalid() throws Exception {
        when(authService.login("buyer@test.com", "wrong"))
                .thenReturn(Optional.empty());

        LoginRequest request = new LoginRequest("buyer@test.com", "wrong");

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"));
    }

    @Test
    void loginShouldReturnForbiddenWhenEmailNotVerified() throws Exception {
        when(authService.login("buyer@test.com", "pass"))
                .thenThrow(new EmailNotVerifiedException("Email not verified"));

        LoginRequest request = new LoginRequest("buyer@test.com", "pass");

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Email not verified"));
    }

    @Test
    void refreshShouldReturnRotatedTokensWhenRefreshTokenValid() throws Exception {
        when(tokenService.refreshTokens("refresh-token")).thenReturn(new TokenResponse(
                "new-access-token",
                "new-refresh-token",
                "Bearer",
                900,
                null
        ));

        RefreshTokenRequest request = new RefreshTokenRequest("refresh-token");

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));
    }

    @Test
    void logoutShouldRevokeRefreshTokenAndReturnNoContent() throws Exception {
        RefreshTokenRequest request = new RefreshTokenRequest("refresh-token");

        mockMvc.perform(post("/api/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNoContent());
    }

    @Test
    void getUserShouldReturnUserWhenExists() throws Exception {
        Role buyerRole = Role.builder()
                .id(UUID.randomUUID())
                .name("BUYER")
                .build();

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("buyer@test.com");
        user.setPassword("pass");
        user.setEnabled(true);
        user.setRoles(Set.of(buyerRole));

        when(authService.findByEmail("buyer@test.com"))
                .thenReturn(Optional.of(user));

        mockMvc.perform(get("/api/v1/auth/user")
                .param("email", "buyer@test.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("buyer@test.com"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void getUserShouldReturnNotFoundWhenMissing() throws Exception {
        when(authService.findByEmail("missing@test.com"))
                .thenReturn(Optional.empty());

        mockMvc.perform(get("/api/v1/auth/user")
                .param("email", "missing@test.com"))
                .andExpect(status().isNotFound());
    }

    @Test
    void registerShouldReturnBadRequestWhenEmailIsBlank() throws Exception {
        RegisterRequest request = new RegisterRequest("", "pass", "BUYER");

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void registerShouldReturnBadRequestWhenRoleNotFound() throws Exception {
        when(authService.register("controller@test.com", "pass", "BUYER"))
                .thenThrow(new RoleNotFoundException("Role not found"));
        RegisterRequest request = new RegisterRequest("controller@test.com", "pass", "BUYER");

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Role not found"));
    }

    @Test
    void getProfileShouldReturnSanitizedProfileWhenUserExists() throws Exception {
        Role buyerRole = Role.builder()
                .id(UUID.randomUUID())
                .name("BUYER")
                .build();

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("buyer@test.com");
        user.setPassword("pass");
        user.setEnabled(true);
        user.setDisplayName("Buyer One");
        user.setAvatarUrl("https://cdn.example.com/avatar.png");
        user.setShippingAddress("Jl. Merdeka No. 1");
        user.setRoles(Set.of(buyerRole));

        when(authService.getProfileByEmail("buyer@test.com"))
                .thenReturn(Optional.of(user));

        mockMvc.perform(get("/api/v1/auth/profile")
                        .param("email", "buyer@test.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("buyer@test.com"))
                .andExpect(jsonPath("$.displayName").value("Buyer One"))
                .andExpect(jsonPath("$.avatarUrl").value("https://cdn.example.com/avatar.png"))
                .andExpect(jsonPath("$.shippingAddress").value("Jl. Merdeka No. 1"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void updateProfileShouldReturnUpdatedSanitizedProfile() throws Exception {
        Role buyerRole = Role.builder()
                .id(UUID.randomUUID())
                .name("BUYER")
                .build();

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("buyer@test.com");
        user.setPassword("pass");
        user.setEnabled(true);
        user.setDisplayName("Buyer Updated");
        user.setAvatarUrl("https://cdn.example.com/new-avatar.png");
        user.setShippingAddress("Jl. Sudirman No. 2");
        user.setRoles(Set.of(buyerRole));

        when(authService.updateProfile(
                "buyer@test.com",
                "Buyer Updated",
                "https://cdn.example.com/new-avatar.png",
                "Jl. Sudirman No. 2"
        )).thenReturn(Optional.of(user));

        UpdateProfileRequest request = new UpdateProfileRequest(
                "buyer@test.com",
                "Buyer Updated",
                "https://cdn.example.com/new-avatar.png",
                "Jl. Sudirman No. 2"
        );

        mockMvc.perform(put("/api/v1/auth/profile")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("buyer@test.com"))
                .andExpect(jsonPath("$.displayName").value("Buyer Updated"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void verifyEmailShouldReturnOkWhenTokenValid() throws Exception {
        when(authService.verifyEmail("valid-token")).thenReturn(true);
        VerifyEmailRequest request = new VerifyEmailRequest("valid-token");

        mockMvc.perform(post("/api/v1/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("Email verified"));
    }

    @Test
    void verifyEmailShouldReturnBadRequestWhenTokenInvalid() throws Exception {
        when(authService.verifyEmail("invalid-token")).thenReturn(false);
        VerifyEmailRequest request = new VerifyEmailRequest("invalid-token");

        mockMvc.perform(post("/api/v1/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Invalid or expired verification token"));
    }

    @Test
    void resendVerificationShouldReturnNoContent() throws Exception {
        ResendVerificationRequest request = new ResendVerificationRequest("buyer@test.com");

        mockMvc.perform(post("/api/v1/auth/resend-verification")
                        .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNoContent());
    }

    @Test
    void getSessionsShouldReturnActiveSessionsForUser() throws Exception {
        when(tokenService.listActiveSessions("buyer@test.com")).thenReturn(List.of(
                new SessionResponse(UUID.randomUUID(), "buyer@test.com", false, "2099-01-01T00:00:00Z")
        ));

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .param("email", "buyer@test.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].email").value("buyer@test.com"))
                .andExpect(jsonPath("$[0].revoked").value(false));
    }

    @Test
    void disableUserShouldReturnNoContentWhenUserDisabled() throws Exception {
        when(authService.disableUser("buyer@test.com")).thenReturn(Optional.of(new User()));

        mockMvc.perform(post("/api/v1/auth/admin/disable-user")
                .param("email", "buyer@test.com"))
                .andExpect(status().isNoContent());
    }

    @Test
    void oauthLoginShouldReturnTokenResponse() throws Exception {
        Role buyerRole = Role.builder()
                .id(UUID.randomUUID())
                .name("BUYER")
                .build();
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("oauth@test.com")
                .enabled(true)
                .emailVerified(true)
                .roles(Set.of(buyerRole))
                .build();

        when(authService.oauthLogin("google", "google-id-token"))
                .thenReturn(user);
        when(tokenService.issueTokens(user)).thenReturn(new TokenResponse(
                "oauth-access-token",
                "oauth-refresh-token",
                "Bearer",
                900,
                null
        ));

        OAuthLoginRequest request = new OAuthLoginRequest(
                "google",
                "google-id-token"
        );

        mockMvc.perform(post("/api/v1/auth/oauth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("oauth-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("oauth-refresh-token"));
    }

    @Test
    void oauthLoginShouldReturnBadRequestWhenProviderUnsupported() throws Exception {
        when(authService.oauthLogin("github", "provider-token"))
                .thenThrow(new UnsupportedOAuthProviderException("Unsupported OAuth provider"));

        OAuthLoginRequest request = new OAuthLoginRequest("github", "provider-token");

        mockMvc.perform(post("/api/v1/auth/oauth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Unsupported OAuth provider"));
    }

    @Test
    void oauthLoginShouldReturnUnauthorizedWhenGoogleTokenInvalid() throws Exception {
        when(authService.oauthLogin("google", "invalid-id-token"))
                .thenThrow(new InvalidOAuthTokenException("Invalid Google ID token"));

        OAuthLoginRequest request = new OAuthLoginRequest("google", "invalid-id-token");

        mockMvc.perform(post("/api/v1/auth/oauth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid Google ID token"));
    }

    @Test
    void checkPermissionShouldReturnAllowedFlag() throws Exception {
        when(authService.hasPermission("buyer@test.com", "bid:place")).thenReturn(true);

        mockMvc.perform(get("/api/v1/auth/permissions/check")
                        .param("email", "buyer@test.com")
                        .param("permission", "bid:place"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true));
    }

    @Test
    void setupTwoFactorShouldReturnSecretAndQrCodeUrl() throws Exception {
        when(authService.setupTwoFactor("buyer@test.com"))
                .thenReturn(new id.ac.ui.cs.advprog.bidmartauthservice.dto.TwoFactorSetupResponse(
                        "JBSWY3DPEHPK3PXP",
                        "otpauth://totp/BidMart:buyer@test.com?secret=JBSWY3DPEHPK3PXP&issuer=BidMart"
                ));

        mockMvc.perform(post("/api/v1/auth/2fa/setup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"buyer@test.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret").value("JBSWY3DPEHPK3PXP"))
                .andExpect(jsonPath("$.qrCodeUrl").value("otpauth://totp/BidMart:buyer@test.com?secret=JBSWY3DPEHPK3PXP&issuer=BidMart"));
    }

    @Test
    void verifyTwoFactorShouldActivateFeature() throws Exception {
        when(authService.verifyTwoFactor("buyer@test.com", "123456")).thenReturn(true);

        mockMvc.perform(post("/api/v1/auth/2fa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"buyer@test.com\",\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true));
    }

    @Test
    void disableTwoFactorShouldTurnOffFeature() throws Exception {
        when(authService.disableTwoFactor("buyer@test.com", "123456")).thenReturn(true);

        mockMvc.perform(post("/api/v1/auth/2fa/disable")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"buyer@test.com\",\"code\":\"123456\"}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void createRoleShouldReturnRoleWithPermissions() throws Exception {
        Permission bidPlace = Permission.builder().id(UUID.randomUUID()).name("bid:place").build();
        Role bidder = Role.builder()
                .id(UUID.randomUUID())
                .name("BIDDER")
                .permissions(Set.of(bidPlace))
                .build();

        when(authService.createRole("BIDDER", List.of("bid:place"))).thenReturn(bidder);

        mockMvc.perform(post("/api/v1/auth/roles")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"BIDDER\",\"permissions\":[\"bid:place\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("BIDDER"))
                .andExpect(jsonPath("$.permissions[0]").value("bid:place"));
    }

    @Test
    void assignUserRoleShouldReturnUpdatedUser() throws Exception {
        UUID userId = UUID.randomUUID();
        Role sellerRole = Role.builder().id(UUID.randomUUID()).name("SELLER").build();
        User user = User.builder()
                .id(userId)
                .email("seller@test.com")
                .enabled(true)
                .roles(Set.of(sellerRole))
                .build();

        when(authService.assignUserRole(userId, "SELLER")).thenReturn(Optional.of(user));

        mockMvc.perform(put("/api/v1/auth/users/{userId}/roles", userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"SELLER\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("seller@test.com"))
                .andExpect(jsonPath("$.roles[0].name").value("SELLER"));
    }

    @Test
    void revokeSessionShouldReturnNoContent() throws Exception {
        UUID sessionId = UUID.randomUUID();

        mockMvc.perform(delete("/api/v1/auth/sessions/{sessionId}", sessionId))
                .andExpect(status().isNoContent());

        verify(tokenService).revokeSessionByTokenId(sessionId);
    }
}
