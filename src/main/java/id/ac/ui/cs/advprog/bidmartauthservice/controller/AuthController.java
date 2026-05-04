package id.ac.ui.cs.advprog.bidmartauthservice.controller;

import id.ac.ui.cs.advprog.bidmartauthservice.annotation.RequirePermission;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.AssignRoleRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.AuthUserResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.CreateRoleRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.LoginRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.OAuthLoginRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.RefreshTokenRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.RegisterRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.ResendVerificationRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.RoleResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.SetPasswordRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.SessionResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.TokenResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.TwoFactorEmailRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.TwoFactorLoginVerifyRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.TwoFactorSetupResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.TwoFactorVerifyRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.UpdateProfileRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.UserProfileResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.VerifyEmailRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.service.AuthService;
import id.ac.ui.cs.advprog.bidmartauthservice.service.TokenService;
import id.ac.ui.cs.advprog.bidmartauthservice.service.ratelimit.AuthRateLimiter;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final String INVALID_TWO_FACTOR_CODE = "Invalid two factor code";

    private final AuthService authService;
    private final TokenService tokenService;
    private final AuthRateLimiter authRateLimiter;

    @PostMapping("/register")
    public ResponseEntity<AuthUserResponse> register(@Valid @RequestBody RegisterRequest request) {

        User user = authService.register(
                request.email(),
                request.password(),
                request.role()
        );

        return ResponseEntity.ok(AuthUserResponse.fromUser(user));
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(
        @Valid @RequestBody LoginRequest request,
        @RequestHeader(value = "User-Agent", defaultValue = "Unknown Device") String userAgent
    ) {
        authRateLimiter.assertAllowed("login", request.email());

        User user = authService.login(request.email(), request.password());

        if (user.isTwoFactorEnabled()) {
            return ResponseEntity.ok(tokenService.issueTwoFactorChallenge(user));
        }
        return ResponseEntity.ok(tokenService.issueTokens(user, userAgent));
    }

    @PostMapping("/2fa/login-verify")
    public ResponseEntity<Object> verifyTwoFactorLogin(
        @Valid @RequestBody TwoFactorLoginVerifyRequest request,
        @RequestHeader(value = "User-Agent", defaultValue = "Unknown Device") String userAgent
    ) {
        authRateLimiter.assertAllowed("2fa-login-verify", request.challengeToken());
        User user = tokenService.verifyTwoFactorChallenge(request.challengeToken());
        
        if (!authService.verifyTwoFactorCode(user.getEmail(), request.code())) {
            return ResponseEntity.status(401).body(INVALID_TWO_FACTOR_CODE);
        }
        
        return ResponseEntity.ok(tokenService.issueTokens(user, userAgent));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        authRateLimiter.assertAllowed("refresh", request.refreshToken());
        return ResponseEntity.ok(tokenService.refreshTokens(request.refreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        tokenService.revokeRefreshToken(request.refreshToken());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/user")
    public ResponseEntity<AuthUserResponse> getUser(@RequestParam String email) {

        return authService.findByEmail(email)
                .map(AuthUserResponse::fromUser)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/profile")
    public ResponseEntity<UserProfileResponse> getProfile(@RequestParam String email) {
        return authService.getProfileByEmail(email)
                .map(UserProfileResponse::fromUser)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/profile")
    public ResponseEntity<UserProfileResponse> updateProfile(@Valid @RequestBody UpdateProfileRequest request) {
        return authService.updateProfile(
                        request.email(),
                        request.displayName(),
                        request.avatarUrl(),
                        request.shippingAddress())
                .map(UserProfileResponse::fromUser)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/password")
    public ResponseEntity<Void> updatePassword(
            @Valid @RequestBody SetPasswordRequest request,
            HttpServletRequest httpRequest
    ) {
        String authenticatedEmail = (String) httpRequest.getAttribute("userEmail");
        if (authenticatedEmail == null || authenticatedEmail.isBlank()) {
            return ResponseEntity.status(401).build();
        }
        if (!authenticatedEmail.equalsIgnoreCase(request.email())) {
            return ResponseEntity.status(403).build();
        }

        return authService.updatePassword(authenticatedEmail, request.password())
                .map(user -> ResponseEntity.noContent().<Void>build())
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        boolean verified = authService.verifyEmail(request.token());
        if (verified) {
            return ResponseEntity.ok("Email verified");
        }
        return ResponseEntity.badRequest().body("Invalid or expired verification token");
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        authService.resendVerification(request.email());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/sessions")
    public ResponseEntity<List<SessionResponse>> getActiveSessions(@RequestParam String email) {
        return ResponseEntity.ok(tokenService.listActiveSessions(email));
    }

    @PostMapping("/admin/disable-user")
    @RequirePermission("admin:users")
    public ResponseEntity<Void> disableUser(@RequestParam String email) {
        return authService.disableUser(email).map(user -> {
            tokenService.revokeAllSessionsForUser(user.getId());
            return ResponseEntity.noContent().<Void>build();
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/oauth/login")
    public ResponseEntity<TokenResponse> oauthLogin(
        @Valid @RequestBody OAuthLoginRequest request,
        @RequestHeader(value = "User-Agent", defaultValue = "Unknown Device") String userAgent
    ) {
        User user = authService.oauthLogin(
                request.provider(),
                request.idToken()
        );
        return ResponseEntity.ok(tokenService.issueTokens(user, userAgent));
    }

    @PostMapping("/oauth/link")
    public ResponseEntity<Void> linkOAuth(
        @Valid @RequestBody OAuthLoginRequest request,
        HttpServletRequest httpRequest
    ) {
        String authenticatedEmail = (String) httpRequest.getAttribute("userEmail");
        if (authenticatedEmail == null || authenticatedEmail.isBlank()) {
            return ResponseEntity.status(401).build();
        }

        authService.linkOAuth(authenticatedEmail, request.provider(), request.idToken());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/permissions/check")
    public ResponseEntity<Map<String, Boolean>> checkPermission(
            @RequestParam String email,
            @RequestParam String permission
    ) {
        return ResponseEntity.ok(Map.of("allowed", authService.hasPermission(email, permission)));
    }

    @PostMapping("/2fa/setup")
    public ResponseEntity<TwoFactorSetupResponse> setupTwoFactor(@Valid @RequestBody TwoFactorEmailRequest request) {
        return ResponseEntity.ok(authService.setupTwoFactor(request.email()));
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<Object> verifyTwoFactor(@Valid @RequestBody TwoFactorVerifyRequest request) {
        authRateLimiter.assertAllowed("2fa-verify", request.email());
        boolean enabled = authService.verifyTwoFactor(request.email(), request.code());
        if (!enabled) {
            return ResponseEntity.badRequest().body(Map.of("message", INVALID_TWO_FACTOR_CODE));
        }
        return ResponseEntity.ok(Map.of("enabled", true));
    }

    @PostMapping("/2fa/disable")
    public ResponseEntity<Object> disableTwoFactor(@Valid @RequestBody TwoFactorVerifyRequest request) {
        authRateLimiter.assertAllowed("2fa-disable", request.email());
        boolean disabled = authService.disableTwoFactor(request.email(), request.code());
        if (!disabled) {
            return ResponseEntity.badRequest().body(Map.of("message", INVALID_TWO_FACTOR_CODE));
        }
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/roles")
    @RequirePermission("admin:roles")
    public ResponseEntity<RoleResponse> createRole(@Valid @RequestBody CreateRoleRequest request) {
        return ResponseEntity.ok(RoleResponse.fromRole(authService.createRole(request.name(), request.permissions())));
    }

    @PutMapping("/users/{userId}/roles")
    @RequirePermission("admin:roles")
    public ResponseEntity<AuthUserResponse> assignUserRole(
            @PathVariable UUID userId,
            @Valid @RequestBody AssignRoleRequest request
    ) {
        return authService.assignUserRole(userId, request.role())
                .map(AuthUserResponse::fromUser)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<Void> revokeSession(@PathVariable UUID sessionId) {
        tokenService.revokeSessionByTokenId(sessionId);
        return ResponseEntity.noContent().build();
    }
}
