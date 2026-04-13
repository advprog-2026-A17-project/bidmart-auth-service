package id.ac.ui.cs.advprog.bidmartauthservice.controller;

import id.ac.ui.cs.advprog.bidmartauthservice.dto.LoginRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.RegisterRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.AuthUserResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.RefreshTokenRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.ResendVerificationRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.UpdateProfileRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.UserProfileResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.VerifyEmailRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.service.AuthService;
import id.ac.ui.cs.advprog.bidmartauthservice.service.TokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;

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
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {

        Optional<User> user = authService.login(
                request.email(),
                request.password()
        );

        if (user.isPresent()) {
            return ResponseEntity.ok(tokenService.issueTokens(user.get()));
        }

        return ResponseEntity.status(401).body("Invalid credentials");
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(tokenService.refreshTokens(request.refreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        tokenService.revokeRefreshToken(request.refreshToken());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/user")
    public ResponseEntity<?> getUser(@RequestParam String email) {

        return authService.findByEmail(email)
                .map(AuthUserResponse::fromUser)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(@RequestParam String email) {
        return authService.getProfileByEmail(email)
                .map(UserProfileResponse::fromUser)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(@Valid @RequestBody UpdateProfileRequest request) {
        return authService.updateProfile(
                        request.email(),
                        request.displayName(),
                        request.avatarUrl(),
                        request.shippingAddress())
                .map(UserProfileResponse::fromUser)
                .map(ResponseEntity::ok)
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
}
