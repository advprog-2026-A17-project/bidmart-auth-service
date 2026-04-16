package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Permission;
import id.ac.ui.cs.advprog.bidmartauthservice.model.EmailVerificationToken;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.RoleRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.UserRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.EmailVerificationTokenRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.EmailNotVerifiedException;
import id.ac.ui.cs.advprog.bidmartauthservice.service.policy.LoginEligibilityPolicy;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@Tag("unit")
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private EmailVerificationTokenRepository emailVerificationTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthEventPublisher authEventPublisher;

    @Mock
    private LoginEligibilityPolicy loginEligibilityPolicy;

    @Mock
    private VerificationEmailSender verificationEmailSender;

    @InjectMocks
    private AuthService authService;

    @Test
    void registerShouldSaveEnabledUserWhenEmailIsAvailable() {
        String email = "service@test.com";
        String password = "pass";
        String roleName = "BUYER";

        Role role = Role.builder()
            .id(UUID.randomUUID())
            .name(roleName)
            .build();

        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(roleRepository.findByName(roleName)).thenReturn(Optional.of(role));
        when(passwordEncoder.encode(password)).thenReturn("encoded-pass");
        when(userRepository.save(any(User.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        User saved = authService.register(email, password, roleName);

        assertNotNull(saved);
        assertNotNull(saved.getId());
        assertEquals(email, saved.getEmail());
        assertEquals("encoded-pass", saved.getPassword());
        assertTrue(saved.isEnabled());
        assertFalse(saved.isEmailVerified());
        assertNull(saved.getVerificationToken());
        assertNull(saved.getVerificationTokenExpiresAt());
        assertNotNull(saved.getRoles());
        assertTrue(saved.getRoles().contains(role));

        ArgumentCaptor<EmailVerificationToken> tokenCaptor = ArgumentCaptor.forClass(EmailVerificationToken.class);
        ArgumentCaptor<String> rawTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailVerificationTokenRepository).save(tokenCaptor.capture());
        verify(verificationEmailSender).sendVerificationEmail(eq(saved), rawTokenCaptor.capture());
        assertEquals(64, tokenCaptor.getValue().getTokenHash().length());
        assertNotEquals(tokenCaptor.getValue().getTokenHash(), rawTokenCaptor.getValue());
        assertNotNull(tokenCaptor.getValue().getExpiresAt());

        verify(userRepository).findByEmail(email);
        verify(roleRepository).findByName(roleName);
        verify(passwordEncoder).encode(password);
        verify(userRepository).save(any(User.class));
        verify(authEventPublisher).publishUserRegistered(saved);
    }

    @Test
    void registerShouldThrowWhenEmailAlreadyRegistered() {
        String email = "service@test.com";
        User existingUser = User.builder().email(email).build();

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(existingUser));

        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> authService.register(email, "pass", "BUYER")
        );

        assertEquals("Email already registered", exception.getMessage());
        verify(userRepository).findByEmail(email);
        verify(roleRepository, never()).findByName(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void loginShouldReturnUserWhenCredentialsAreValid() {
        String email = "find@test.com";
        String password = "secret";

        User user = new User();
        user.setEmail(email);
        user.setPassword("encoded-secret");
        user.setEnabled(true);
        user.setEmailVerified(true);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(loginEligibilityPolicy.isPasswordCheckAllowed(user)).thenReturn(true);
        when(passwordEncoder.matches(password, "encoded-secret")).thenReturn(true);
        when(loginEligibilityPolicy.resolveSuccessfulLogin(user)).thenReturn(Optional.of(user));

        Optional<User> result = authService.login(email, password);

        assertTrue(result.isPresent());
        assertEquals(email, result.get().getEmail());
        verify(passwordEncoder).matches(password, "encoded-secret");
    }

    @Test
    void loginShouldReturnEmptyWhenPasswordIsInvalid() {
        String email = "find@test.com";

        User user = new User();
        user.setEmail(email);
        user.setPassword("encoded-secret");
        user.setEnabled(true);
        user.setEmailVerified(true);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(loginEligibilityPolicy.isPasswordCheckAllowed(user)).thenReturn(true);
        when(passwordEncoder.matches("wrong-password", "encoded-secret")).thenReturn(false);

        Optional<User> result = authService.login(email, "wrong-password");

        assertFalse(result.isPresent());
        verify(passwordEncoder).matches("wrong-password", "encoded-secret");
    }

    @Test
    void loginShouldReturnEmptyWhenUserIsDisabled() {
        String email = "disabled@test.com";
        String password = "secret";

        User user = new User();
        user.setEmail(email);
        user.setPassword("encoded-secret");
        user.setEmailVerified(true);
        user.setEnabled(false);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(loginEligibilityPolicy.isPasswordCheckAllowed(user)).thenReturn(false);

        Optional<User> result = authService.login(email, password);

        assertFalse(result.isPresent());
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void loginShouldReturnEmptyWhenUserNotFound() {
        when(userRepository.findByEmail("unknown@test.com")).thenReturn(Optional.empty());

        Optional<User> result = authService.login("unknown@test.com", "secret");

        assertFalse(result.isPresent());
    }

    @Test
    void loginShouldThrowWhenEmailNotVerified() {
        String email = "find@test.com";
        String password = "secret";

        User user = new User();
        user.setEmail(email);
        user.setPassword("encoded-secret");
        user.setEnabled(true);
        user.setEmailVerified(false);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(loginEligibilityPolicy.isPasswordCheckAllowed(user)).thenReturn(true);
        when(passwordEncoder.matches(password, "encoded-secret")).thenReturn(true);
        when(loginEligibilityPolicy.resolveSuccessfulLogin(user))
                .thenThrow(new EmailNotVerifiedException("Email not verified"));

        EmailNotVerifiedException exception = assertThrows(
                EmailNotVerifiedException.class,
                () -> authService.login(email, password)
        );
        assertEquals("Email not verified", exception.getMessage());
    }

    @Test
    void findByEmailShouldDelegateToRepository() {
        String email = "find@test.com";

        User user = new User();
        user.setEmail(email);

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(user));

        Optional<User> result = authService.findByEmail(email);

        assertTrue(result.isPresent());
        assertEquals(email, result.get().getEmail());
    }

    @Test
    void getProfileByEmailShouldReturnUserWhenExists() {
        String email = "profile@test.com";
        User user = User.builder().email(email).displayName("Profile User").build();

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        Optional<User> result = authService.getProfileByEmail(email);

        assertTrue(result.isPresent());
        assertEquals("Profile User", result.get().getDisplayName());
    }

    @Test
    void updateProfileShouldUpdateAndPersistFieldsWhenUserExists() {
        String email = "profile@test.com";
        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .displayName("Old Name")
                .avatarUrl("https://cdn.example.com/old-avatar.png")
                .shippingAddress("Old Address")
                .build();

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Optional<User> updated = authService.updateProfile(
                email,
                "New Name",
                "https://cdn.example.com/new-avatar.png",
                "New Address"
        );

        assertTrue(updated.isPresent());
        assertEquals("New Name", updated.get().getDisplayName());
        assertEquals("https://cdn.example.com/new-avatar.png", updated.get().getAvatarUrl());
        assertEquals("New Address", updated.get().getShippingAddress());
        verify(userRepository).save(user);
    }

    @Test
    void verifyEmailShouldMarkUserVerifiedWhenTokenValid() {
        String token = "raw-verification-token";
        String tokenHash = sha256Hex(token);
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("verify@test.com")
                .emailVerified(false)
                .build();
        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(Instant.now().plusSeconds(600))
                .build();

        when(emailVerificationTokenRepository.findByTokenHashAndUsedAtIsNull(tokenHash))
                .thenReturn(Optional.of(verificationToken));
        when(emailVerificationTokenRepository.findByUserAndUsedAtIsNull(user))
                .thenReturn(java.util.List.of(verificationToken));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        boolean verified = authService.verifyEmail(token);

        assertTrue(verified);
        assertTrue(user.isEmailVerified());
        assertNotNull(verificationToken.getUsedAt());
        verify(authEventPublisher).publishEmailVerified(user);
    }

    @Test
    void verifyEmailShouldReturnFalseWhenTokenInvalid() {
        String token = "unknown-token";
        when(emailVerificationTokenRepository.findByTokenHashAndUsedAtIsNull(sha256Hex(token)))
                .thenReturn(Optional.empty());

        boolean verified = authService.verifyEmail(token);

        assertFalse(verified);
        verify(userRepository, never()).save(any(User.class));
        verify(authEventPublisher, never()).publishEmailVerified(any(User.class));
    }

    @Test
    void resendVerificationShouldRotateTokenAndSendEmailForUnverifiedUser() {
        String email = "buyer@test.com";
        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .emailVerified(false)
                .enabled(true)
                .build();

        EmailVerificationToken existingToken = EmailVerificationToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash("oldhash")
                .expiresAt(Instant.now().plusSeconds(600))
                .lastSentAt(Instant.now().minusSeconds(300))
                .build();

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(emailVerificationTokenRepository.findFirstByUserAndUsedAtIsNullOrderByCreatedAtDesc(user))
                .thenReturn(Optional.of(existingToken));
        when(emailVerificationTokenRepository.findByUserAndUsedAtIsNull(user))
                .thenReturn(java.util.List.of(existingToken));
        when(emailVerificationTokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        authService.resendVerification(email);

        ArgumentCaptor<String> rawTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(verificationEmailSender).sendVerificationEmail(eq(user), rawTokenCaptor.capture());
        verify(emailVerificationTokenRepository, times(2)).save(any(EmailVerificationToken.class));
        assertNotNull(rawTokenCaptor.getValue());
    }

    @Test
    void disableUserShouldDisableAccountWhenEmailExists() {
        String email = "disable@test.com";
        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .enabled(true)
                .build();
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Optional<User> disabled = authService.disableUser(email);

        assertTrue(disabled.isPresent());
        assertFalse(disabled.get().isEnabled());
        verify(userRepository).save(user);
        verify(authEventPublisher).publishUserDisabled(user);
    }

    @Test
    void oauthLoginShouldCreateVerifiedBuyerWhenEmailNotRegistered() {
        String email = "oauth@test.com";
        Role buyerRole = Role.builder()
                .id(UUID.randomUUID())
                .name("BUYER")
                .build();

        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(roleRepository.findByName("BUYER")).thenReturn(Optional.of(buyerRole));
        when(passwordEncoder.encode(anyString())).thenReturn("encoded-oauth-secret");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User user = authService.oauthLogin("google", "google-user-1", email, "OAuth User");

        assertEquals(email, user.getEmail());
        assertTrue(user.isEmailVerified());
        assertEquals("OAuth User", user.getDisplayName());
        assertTrue(user.getRoles().contains(buyerRole));
    }

    @Test
    void hasPermissionShouldReturnTrueWhenUserRoleContainsPermission() {
        Permission permission = Permission.builder()
                .id(UUID.randomUUID())
                .name("bid:place")
                .build();
        Role buyerRole = Role.builder()
                .id(UUID.randomUUID())
                .name("BUYER")
                .permissions(Set.of(permission))
                .build();
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("rbac@test.com")
                .roles(Set.of(buyerRole))
                .build();

        when(userRepository.findByEmail("rbac@test.com")).thenReturn(Optional.of(user));

        assertTrue(authService.hasPermission("rbac@test.com", "bid:place"));
        assertFalse(authService.hasPermission("rbac@test.com", "auction:create"));
    }

    private String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder();
            for (byte value : bytes) {
                builder.append(String.format("%02x", value));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }
}
