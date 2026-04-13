package id.ac.ui.cs.advprog.bidmartauthservice.controller;

import id.ac.ui.cs.advprog.bidmartauthservice.dto.LoginRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.RegisterRequest;
import id.ac.ui.cs.advprog.bidmartauthservice.dto.AuthUserResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.service.AuthService;
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
            return ResponseEntity.ok(AuthUserResponse.fromUser(user.get()));
        }

        return ResponseEntity.status(401).body("Invalid credentials");
    }

    @GetMapping("/user")
    public ResponseEntity<?> getUser(@RequestParam String email) {

        return authService.findByEmail(email)
                .map(AuthUserResponse::fromUser)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
