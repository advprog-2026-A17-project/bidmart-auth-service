package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Permission;
import id.ac.ui.cs.advprog.bidmartauthservice.model.EmailVerificationToken;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.UnsupportedOAuthProviderException;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.RoleRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.UserRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.EmailVerificationTokenRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.PermissionRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.TwoFactorChallengeRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.EmailNotVerifiedException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.InvalidCredentialsException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.InvalidOAuthTokenException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.UserNotFoundException;
import id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning.WalletProvisioningOutboxService;
import id.ac.ui.cs.advprog.bidmartauthservice.service.security.AuthAuditOutboxService;
import id.ac.ui.cs.advprog.bidmartauthservice.service.policy.LoginEligibilityPolicy;
import id.ac.ui.cs.advprog.bidmartauthservice.service.policy.PasswordPolicy;
import id.ac.ui.cs.advprog.bidmartauthservice.service.oauth.OAuthIdentity;
import id.ac.ui.cs.advprog.bidmartauthservice.service.oauth.OAuthIdentityVerifier;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@Tag("unit")
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private EmailVerificationTokenRepository emailVerificationTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthEventPublisher authEventPublisher;

    @Mock
    private LoginEligibilityPolicy loginEligibilityPolicy;

    @Mock
    private PasswordPolicy passwordPolicy;

    @Mock
    private VerificationEmailSender verificationEmailSender;

    @Mock
    private VerificationTokenCodec verificationTokenCodec;

    @Mock
    private OAuthIdentityVerifier oauthIdentityVerifier;

    @Mock
    private WalletProvisioningOutboxService walletProvisioningOutboxService;

    @Mock
    private AuthAuditOutboxService authAuditOutboxService;

    @Spy
    private TwoFactorTotpService twoFactorTotpService = new TwoFactorTotpService(mock(TwoFactorChallengeRepository.class));

    @InjectMocks
    private AuthService authService;

    private static String currentTotp(String base32Secret) {
        try {
            byte[] key = decodeBase32(base32Secret);
            long counter = Instant.now().getEpochSecond() / 30L;
            byte[] counterBytes = ByteBuffer.allocate(Long.BYTES).putLong(counter).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(counterBytes);
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);
            return String.format("%06d", binary % 1_000_000);
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static byte[] decodeBase32(String value) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int buffer = 0;
        int bitsLeft = 0;
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        for (char character : value.toUpperCase(java.util.Locale.ROOT).toCharArray()) {
            int index = alphabet.indexOf(character);
            if (index < 0) {
                throw new IllegalArgumentException("Invalid base32 secret");
            }
            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                output.write((buffer >> (bitsLeft - 8)) & 0xff);
                bitsLeft -= 8;
            }
        }
        return output.toByteArray();
    }

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
        when(verificationTokenCodec.generateRawToken()).thenReturn("raw-register-token");
        when(verificationTokenCodec.hashToken("raw-register-token")).thenReturn("a".repeat(64));
        when(userRepository.save(any(User.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(emailVerificationTokenRepository.findByUserAndUsedAtIsNull(any(User.class)))
                .thenReturn(java.util.List.of());
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
        verify(passwordPolicy).validate(password);
        verify(roleRepository).findByName(roleName);
        verify(passwordEncoder).encode(password);
        verify(userRepository).save(any(User.class));
        verify(walletProvisioningOutboxService).enqueueWalletProvisionRequested(saved);
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
        verify(walletProvisioningOutboxService, never()).enqueueWalletProvisionRequested(any(User.class));
    }

    @Test
    void registerShouldRejectPasswordThatViolatesPolicy() {
        String email = "service@test.com";
        String password = "weak";

        doThrow(new IllegalArgumentException("Password does not meet policy"))
                .when(passwordPolicy).validate(password);

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> authService.register(email, password, "BUYER")
        );

        assertEquals("Password does not meet policy", exception.getMessage());
        verify(passwordPolicy).validate(password);
        verify(userRepository, never()).findByEmail(anyString());
        verify(userRepository, never()).save(any(User.class));
        verify(walletProvisioningOutboxService, never()).enqueueWalletProvisionRequested(any(User.class));
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

        User result = authService.login(email, password);

        assertNotNull(result);
        assertEquals(email, result.getEmail());
        verify(passwordEncoder).matches(password, "encoded-secret");
    }

    @Test
    void loginShouldThrowWhenPasswordIsInvalid() {
        String email = "find@test.com";

        User user = new User();
        user.setEmail(email);
        user.setPassword("encoded-secret");
        user.setEnabled(true);
        user.setEmailVerified(true);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(loginEligibilityPolicy.isPasswordCheckAllowed(user)).thenReturn(true);
        when(passwordEncoder.matches("wrong-password", "encoded-secret")).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () -> authService.login(email, "wrong-password"));
        verify(passwordEncoder).matches("wrong-password", "encoded-secret");
    }

    @Test
    void loginShouldThrowWhenUserIsDisabled() {
        String email = "disabled@test.com";
        String password = "secret";

        User user = new User();
        user.setEmail(email);
        user.setPassword("encoded-secret");
        user.setEmailVerified(true);
        user.setEnabled(false);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(loginEligibilityPolicy.isPasswordCheckAllowed(user)).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () -> authService.login(email, password));
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void loginShouldThrowWhenUserNotFound() {
        when(userRepository.findByEmail("unknown@test.com")).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> authService.login("unknown@test.com", "secret"));
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
    void setupTwoFactorShouldPersistSecretAndReturnQrCodeUrl() {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("buyer@test.com")
                .build();
        when(userRepository.findByEmail("buyer@test.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        var response = authService.setupTwoFactor("buyer@test.com");

        assertNotNull(response.secret());
        assertTrue(response.qrCodeUrl().startsWith("otpauth://totp/BidMart:buyer@test.com"));
        assertEquals(response.secret(), user.getTwoFactorSecret());
        assertFalse(user.isTwoFactorEnabled());
        verify(userRepository).save(user);
    }

    @Test
    void verifyTwoFactorShouldEnableFeatureWhenCodeIsValid() {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("buyer@test.com")
                .twoFactorSecret("JBSWY3DPEHPK3PXP")
                .twoFactorEnabled(false)
                .build();
        when(userRepository.findByEmail("buyer@test.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        boolean verified = authService.verifyTwoFactor("buyer@test.com", currentTotp("JBSWY3DPEHPK3PXP"));

        assertTrue(verified);
        assertTrue(user.isTwoFactorEnabled());
        verify(userRepository).save(user);
    }

    @Test
    void disableTwoFactorShouldClearSecretWhenCodeIsValid() {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("buyer@test.com")
                .twoFactorSecret("JBSWY3DPEHPK3PXP")
                .twoFactorEnabled(true)
                .build();
        when(userRepository.findByEmail("buyer@test.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        boolean disabled = authService.disableTwoFactor("buyer@test.com", currentTotp("JBSWY3DPEHPK3PXP"));

        assertTrue(disabled);
        assertFalse(user.isTwoFactorEnabled());
        assertNull(user.getTwoFactorSecret());
        verify(userRepository).save(user);
    }

    @Test
    void createRoleShouldReuseExistingPermissionsAndCreateMissingPermissions() {
        Permission existing = Permission.builder().id(UUID.randomUUID()).name("bid:place").build();
        when(permissionRepository.findByName("bid:place")).thenReturn(Optional.of(existing));
        when(permissionRepository.findByName("auction:close")).thenReturn(Optional.empty());
        when(permissionRepository.save(any(Permission.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Role role = authService.createRole("AUCTION_MANAGER", java.util.List.of("bid:place", "auction:close"));

        assertEquals("AUCTION_MANAGER", role.getName());
        assertEquals(2, role.getPermissions().size());
        assertTrue(role.getPermissions().stream().anyMatch(permission -> "bid:place".equals(permission.getName())));
        assertTrue(role.getPermissions().stream().anyMatch(permission -> "auction:close".equals(permission.getName())));
        verify(roleRepository).save(any(Role.class));
        verify(permissionRepository).save(any(Permission.class));
        verify(authAuditOutboxService).enqueueRoleCreated(role);
    }

    @Test
    void assignUserRoleShouldReplaceExistingRoles() {
        UUID userId = UUID.randomUUID();
        Role buyer = Role.builder().id(UUID.randomUUID()).name("BUYER").build();
        Role seller = Role.builder().id(UUID.randomUUID()).name("SELLER").build();
        User user = User.builder()
                .id(userId)
                .email("seller@test.com")
                .roles(Set.of(buyer))
                .build();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(roleRepository.findByName("SELLER")).thenReturn(Optional.of(seller));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Optional<User> updated = authService.assignUserRole(userId, "SELLER");

        assertTrue(updated.isPresent());
        assertEquals(Set.of(seller), updated.get().getRoles());
        verify(userRepository).save(user);
        verify(authAuditOutboxService).enqueueUserRoleChanged(user, seller);
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
        when(verificationTokenCodec.hashToken(token)).thenReturn(tokenHash);
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
        when(verificationTokenCodec.hashToken(token)).thenReturn(sha256Hex(token));
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
        when(verificationTokenCodec.generateRawToken()).thenReturn("raw-resend-token");
        when(verificationTokenCodec.hashToken("raw-resend-token")).thenReturn("b".repeat(64));
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
        verify(authAuditOutboxService).enqueueUserDisabled(user);
    }

    @Test
    void oauthLoginShouldCreateVerifiedBuyerWhenEmailNotRegistered() {
        String email = "oauth@test.com";
        Role buyerRole = Role.builder()
                .id(UUID.randomUUID())
                .name("BUYER")
                .build();
        OAuthIdentity identity = new OAuthIdentity(
                "google-user-1",
                email,
                "OAuth User",
                "https://cdn.example.com/oauth-avatar.png"
        );

        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        when(oauthIdentityVerifier.supports("google")).thenReturn(true);
        when(oauthIdentityVerifier.verify("google-id-token")).thenReturn(identity);
        when(roleRepository.findByName("BUYER")).thenReturn(Optional.of(buyerRole));
        when(passwordEncoder.encode(anyString())).thenReturn("encoded-oauth-secret");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User user = authService.oauthLogin("google", "google-id-token");

        assertEquals(email, user.getEmail());
        assertTrue(user.isEmailVerified());
        assertEquals("OAuth User", user.getDisplayName());
        assertEquals("https://cdn.example.com/oauth-avatar.png", user.getAvatarUrl());
        assertEquals("google", user.getOauthProvider());
        assertEquals("google-user-1", user.getOauthSubject());
        assertTrue(user.getRoles().contains(buyerRole));
    }

    @Test
    void oauthLoginShouldThrowWhenProviderUnsupported() {
        when(oauthIdentityVerifier.supports("github")).thenReturn(false);

        UnsupportedOAuthProviderException exception = assertThrows(
                UnsupportedOAuthProviderException.class,
                () -> authService.oauthLogin("github", "id-token")
        );

        assertEquals("Unsupported OAuth provider", exception.getMessage());
        verify(oauthIdentityVerifier, never()).verify(anyString());
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

    @Test
    void oauthLoginShouldLinkExistingUserWhenEmailMatches() {
        String email = "existing@test.com";
        User existingUser = User.builder()
                .email(email)
                .oauthProvider(null)
                .oauthSubject(null)
                .build();
        OAuthIdentity identity = new OAuthIdentity("google-sub", email, "New Name", "new-avatar");

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(existingUser));
        when(oauthIdentityVerifier.supports("google")).thenReturn(true);
        when(oauthIdentityVerifier.verify("token")).thenReturn(identity);
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        User result = authService.oauthLogin("google", "token");

        assertEquals("google", result.getOauthProvider());
        assertEquals("google-sub", result.getOauthSubject());
        assertTrue(result.isEmailVerified());
        assertEquals("New Name", result.getDisplayName());
    }

    @Test
    void oauthLoginShouldThrowWhenOauthIdentityMismatches() {
        String email = "linked@test.com";
        User linkedUser = User.builder()
                .email(email)
                .oauthProvider("google")
                .oauthSubject("original-sub")
                .build();
        OAuthIdentity mismatchIdentity = new OAuthIdentity("hacker-sub", email, "Name", "url");

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(linkedUser));
        when(oauthIdentityVerifier.supports("google")).thenReturn(true);
        when(oauthIdentityVerifier.verify("token")).thenReturn(mismatchIdentity);

        assertThrows(InvalidOAuthTokenException.class, () -> authService.oauthLogin("google", "token"));
    }

    @Test
    void verifyEmailShouldReturnFalseWhenTokenExpired() {
        String token = "expired-token";
        String hash = "hash";
        when(verificationTokenCodec.hashToken(token)).thenReturn(hash);
        EmailVerificationToken expiredToken = EmailVerificationToken.builder()
                .expiresAt(Instant.now().minusSeconds(3600))
                .build();

        when(emailVerificationTokenRepository.findByTokenHashAndUsedAtIsNull(hash))
                .thenReturn(Optional.of(expiredToken));

        assertFalse(authService.verifyEmail(token));
        assertNotNull(expiredToken.getUsedAt());
        verify(emailVerificationTokenRepository).save(expiredToken);
    }

    @Test
    void verifyEmailShouldReturnFalseWhenUserAlreadyVerified() {
        String token = "valid-token";
        String hash = "hash";
        User user = User.builder().emailVerified(true).build();
        EmailVerificationToken tokenRecord = EmailVerificationToken.builder()
                .user(user)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(verificationTokenCodec.hashToken(token)).thenReturn(hash);
        when(emailVerificationTokenRepository.findByTokenHashAndUsedAtIsNull(hash))
                .thenReturn(Optional.of(tokenRecord));

        assertFalse(authService.verifyEmail(token));
        verify(userRepository, never()).save(any());
    }

    @Test
    void hasPermissionShouldHandleNullPermissionsSafely() {
        Role roleWithNoPerms = Role.builder().permissions(null).build();
        User user = User.builder().roles(Set.of(roleWithNoPerms)).build();

        when(userRepository.findByEmail("test@test.com")).thenReturn(Optional.of(user));

        assertFalse(authService.hasPermission("test@test.com", "any:perm"));
    }

    @Test
    void assignUserRoleShouldReturnEmptyWhenUserNotFound() {
        UUID userId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        Optional<User> result = authService.assignUserRole(userId, "ADMIN");

        assertTrue(result.isEmpty());
    }

    @Test
    void verifyTwoFactorCodeShouldReturnBooleanWithoutEnablingFeature() {
        User user = User.builder().twoFactorSecret("SECRET").build();
        when(userRepository.findByEmail("2fa@test.com")).thenReturn(Optional.of(user));
        
        assertTrue(authService.verifyTwoFactorCode("2fa@test.com", currentTotp("SECRET")));
        assertFalse(authService.verifyTwoFactorCode("2fa@test.com", "000000"));
    }

    @Test
    void resendVerificationShouldRespectCooldown() {
        User user = User.builder().emailVerified(false).build();
        EmailVerificationToken recentToken = EmailVerificationToken.builder()
                .lastSentAt(Instant.now().minusSeconds(10))
                .build();

        when(userRepository.findByEmail("test@test.com")).thenReturn(Optional.of(user));
        when(emailVerificationTokenRepository.findFirstByUserAndUsedAtIsNullOrderByCreatedAtDesc(user))
                .thenReturn(Optional.of(recentToken));

        authService.resendVerification("test@test.com");

        verify(verificationEmailSender, never()).sendVerificationEmail(any(), anyString());
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