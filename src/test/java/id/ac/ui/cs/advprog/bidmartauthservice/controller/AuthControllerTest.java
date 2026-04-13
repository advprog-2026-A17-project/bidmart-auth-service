package id.ac.ui.cs.advprog.bidmartauthservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.LoginRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.RefreshTokenRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.RegisterRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.ResendVerificationRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.TokenResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.UpdateProfileRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.VerifyEmailRequest;
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

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
}
