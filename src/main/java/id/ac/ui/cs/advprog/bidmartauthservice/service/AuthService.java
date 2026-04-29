package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.dto.TwoFactorSetupResponse;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Permission;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.model.EmailVerificationToken;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.EmailVerificationTokenRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.PermissionRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.RoleRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.UserRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning.WalletProvisioningOutboxService;
import id.ac.ui.cs.advprog.bidmartauthservice.service.oauth.OAuthIdentity;
import id.ac.ui.cs.advprog.bidmartauthservice.service.oauth.OAuthIdentityVerifier;
import id.ac.ui.cs.advprog.bidmartauthservice.service.policy.LoginEligibilityPolicy;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.EmailAlreadyRegisteredException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.InvalidOAuthTokenException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.RoleNotFoundException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.UnsupportedOAuthProviderException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthEventPublisher authEventPublisher;
    private final LoginEligibilityPolicy loginEligibilityPolicy;
    private final VerificationEmailSender verificationEmailSender;
    private final VerificationTokenCodec verificationTokenCodec;
    private final OAuthIdentityVerifier oauthIdentityVerifier;
    private final WalletProvisioningOutboxService walletProvisioningOutboxService;

    @Value("${app.auth.email-verification.token-ttl-seconds:86400}")
    private long verificationTokenTtlSeconds;

    @Value("${app.auth.email-verification.resend-cooldown-seconds:60}")
    private long resendCooldownSeconds;

    private static final String TOTP_ISSUER = "BidMart";
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Transactional
    public User register(String email, String password, String roleName) {

        // cek apakah email sudah ada
        if (userRepository.findByEmail(email).isPresent()) {
            throw new EmailAlreadyRegisteredException("Email already registered");
        }

        // cari role
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new RoleNotFoundException("Role not found"));

        // buat user
        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .password(passwordEncoder.encode(password))
                .enabled(true)
                .emailVerified(false)
                .roles(Set.of(role))
                .build();

        User savedUser = userRepository.save(user);
        issueVerificationToken(savedUser, Instant.now(), false);
        walletProvisioningOutboxService.enqueueWalletProvisionRequested(savedUser);
        authEventPublisher.publishUserRegistered(savedUser);
        return savedUser;
    }

    public Optional<User> login(String email, String password) {
        return userRepository.findByEmail(email)
                .filter(loginEligibilityPolicy::isPasswordCheckAllowed)
                .filter(user -> passwordEncoder.matches(password, user.getPassword()))
                .flatMap(loginEligibilityPolicy::resolveSuccessfulLogin);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> getProfileByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> updateProfile(
            String email,
            String displayName,
            String avatarUrl,
            String shippingAddress
    ) {
        return userRepository.findByEmail(email).map(user -> {
            user.setDisplayName(displayName);
            user.setAvatarUrl(avatarUrl);
            user.setShippingAddress(shippingAddress);
            return userRepository.save(user);
        });
    }

    public boolean verifyEmail(String token) {
        Instant now = Instant.now();
        String tokenHash = verificationTokenCodec.hashToken(token);

        Optional<EmailVerificationToken> tokenRecord = emailVerificationTokenRepository
                .findByTokenHashAndUsedAtIsNull(tokenHash);
        if (tokenRecord.isEmpty()) {
            return false;
        }

        EmailVerificationToken verificationToken = tokenRecord.get();
        if (verificationToken.getExpiresAt() == null || !verificationToken.getExpiresAt().isAfter(now)) {
            verificationToken.setUsedAt(now);
            emailVerificationTokenRepository.save(verificationToken);
            return false;
        }

        User user = verificationToken.getUser();
        if (user == null || user.isEmailVerified()) {
            verificationToken.setUsedAt(now);
            emailVerificationTokenRepository.save(verificationToken);
            return false;
        }

        user.setEmailVerified(true);
        userRepository.save(user);

        verificationToken.setUsedAt(now);
        emailVerificationTokenRepository.save(verificationToken);
        invalidateActiveTokens(user, now);

        authEventPublisher.publishEmailVerified(user);
        return true;
    }

    public void resendVerification(String email) {
        userRepository.findByEmail(email)
                .filter(user -> !user.isEmailVerified())
                .ifPresent(user -> {
                    issueVerificationToken(user, Instant.now(), true);
                });
    }

    public Optional<User> disableUser(String email) {
        return userRepository.findByEmail(email).map(user -> {
            user.setEnabled(false);
            User savedUser = userRepository.save(user);
            authEventPublisher.publishUserDisabled(savedUser);
            return savedUser;
        });
    }

    public User oauthLogin(String provider, String idToken) {
        if (!oauthIdentityVerifier.supports(provider)) {
            throw new UnsupportedOAuthProviderException("Unsupported OAuth provider");
        }

        OAuthIdentity identity = oauthIdentityVerifier.verify(idToken);
        Optional<User> existingUser = userRepository.findByEmail(identity.email());

        if (existingUser.isPresent()) {
            return updateExistingOAuthUser(existingUser.get(), provider, identity);
        }

        Role buyerRole = roleRepository.findByName("BUYER")
                .orElseGet(() -> roleRepository.save(Role.builder()
                        .id(UUID.randomUUID())
                        .name("BUYER")
                        .build()));

        User user = User.builder()
                .id(UUID.randomUUID())
                .email(identity.email())
                .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                .enabled(true)
                .emailVerified(true)
                .verificationToken(null)
                .verificationTokenExpiresAt(null)
                .oauthProvider(provider.toLowerCase(Locale.ROOT))
                .oauthSubject(identity.subject())
                .displayName(identity.displayName())
                .avatarUrl(identity.avatarUrl())
                .roles(Set.of(buyerRole))
                .build();

        return userRepository.save(user);
    }

    private User updateExistingOAuthUser(User existingUser, String provider, OAuthIdentity identity) {
        boolean oauthAlreadyLinked = !isBlank(existingUser.getOauthProvider())
                || !isBlank(existingUser.getOauthSubject());
        if (oauthAlreadyLinked && !isMatchingOauthIdentity(existingUser, provider, identity)) {
            throw new InvalidOAuthTokenException("Google account is not linked to this user");
        }

        existingUser.setOauthProvider(provider.toLowerCase(Locale.ROOT));
        existingUser.setOauthSubject(identity.subject());
        existingUser.setEmailVerified(true);

        if (isBlank(existingUser.getDisplayName())) {
            existingUser.setDisplayName(identity.displayName());
        }
        if (isBlank(existingUser.getAvatarUrl())) {
            existingUser.setAvatarUrl(identity.avatarUrl());
        }

        return userRepository.save(existingUser);
    }

    private boolean isMatchingOauthIdentity(User user, String provider, OAuthIdentity identity) {
        return provider.equalsIgnoreCase(user.getOauthProvider())
                && identity.subject().equals(user.getOauthSubject());
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public boolean hasPermission(String email, String permissionName) {
        return userRepository.findByEmail(email)
                .map(user -> user.getRoles().stream()
                        .flatMap(role -> role.getPermissions() == null
                                ? java.util.stream.Stream.empty()
                                : role.getPermissions().stream())
                        .anyMatch(permission -> permissionName.equals(permission.getName())))
                .orElse(false);
    }

    @Transactional
    public TwoFactorSetupResponse setupTwoFactor(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        String secret = generateBase32Secret();
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
        return new TwoFactorSetupResponse(secret, buildOtpAuthUrl(email, secret));
    }

    @Transactional
    public boolean verifyTwoFactor(String email, String code) {
        return userRepository.findByEmail(email)
                .filter(user -> isTotpValid(user.getTwoFactorSecret(), code))
                .map(user -> {
                    user.setTwoFactorEnabled(true);
                    userRepository.save(user);
                    return true;
                })
                .orElse(false);
    }

    @Transactional
    public boolean disableTwoFactor(String email, String code) {
        return userRepository.findByEmail(email)
                .filter(user -> user.isTwoFactorEnabled())
                .filter(user -> isTotpValid(user.getTwoFactorSecret(), code))
                .map(user -> {
                    user.setTwoFactorEnabled(false);
                    user.setTwoFactorSecret(null);
                    userRepository.save(user);
                    return true;
                })
                .orElse(false);
    }

    @Transactional
    public Role createRole(String roleName, List<String> permissionNames) {
        Set<Permission> permissions = new LinkedHashSet<>();
        for (String permissionName : permissionNames) {
            String normalizedPermission = permissionName.trim();
            Permission permission = permissionRepository.findByName(normalizedPermission)
                    .orElseGet(() -> permissionRepository.save(Permission.builder()
                            .id(UUID.randomUUID())
                            .name(normalizedPermission)
                            .build()));
            permissions.add(permission);
        }

        Role role = Role.builder()
                .id(UUID.randomUUID())
                .name(roleName.trim().toUpperCase(Locale.ROOT))
                .permissions(permissions)
                .build();
        return roleRepository.save(role);
    }

    @Transactional
    public Optional<User> assignUserRole(UUID userId, String roleName) {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            return Optional.empty();
        }

        Role role = roleRepository.findByName(roleName.trim().toUpperCase(Locale.ROOT))
                .orElseThrow(() -> new RoleNotFoundException("Role not found"));
        User updatedUser = user.get();
        updatedUser.setRoles(Set.of(role));
        return Optional.of(userRepository.save(updatedUser));
    }

    private void issueVerificationToken(User user, Instant now, boolean enforceCooldown) {
        if (enforceCooldown && isWithinCooldownWindow(user, now)) {
            return;
        }

        invalidateActiveTokens(user, now);

        String rawToken = verificationTokenCodec.generateRawToken();
        EmailVerificationToken token = EmailVerificationToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash(verificationTokenCodec.hashToken(rawToken))
                .expiresAt(now.plusSeconds(verificationTokenTtlSeconds))
                .createdAt(now)
                .lastSentAt(now)
                .build();

        emailVerificationTokenRepository.save(token);
        verificationEmailSender.sendVerificationEmail(user, rawToken);
    }

    private boolean isWithinCooldownWindow(User user, Instant now) {
        return emailVerificationTokenRepository
                .findFirstByUserAndUsedAtIsNullOrderByCreatedAtDesc(user)
                .map(token -> token.getLastSentAt() != null
                        && token.getLastSentAt().isAfter(now.minusSeconds(resendCooldownSeconds)))
                .orElse(false);
    }

    private void invalidateActiveTokens(User user, Instant now) {
        List<EmailVerificationToken> activeTokens = emailVerificationTokenRepository.findByUserAndUsedAtIsNull(user);
        for (EmailVerificationToken activeToken : activeTokens) {
            activeToken.setUsedAt(now);
            emailVerificationTokenRepository.save(activeToken);
        }
    }

    private String generateBase32Secret() {
        byte[] randomBytes = new byte[20];
        SECURE_RANDOM.nextBytes(randomBytes);
        return encodeBase32(randomBytes);
    }

    private String buildOtpAuthUrl(String email, String secret) {
        String issuer = URLEncoder.encode(TOTP_ISSUER, StandardCharsets.UTF_8);
        return "otpauth://totp/" + TOTP_ISSUER + ":" + email + "?secret=" + secret + "&issuer=" + issuer;
    }

    private boolean isTotpValid(String secret, String code) {
        if (secret == null || code == null || !code.matches("\\d{6}")) {
            return false;
        }
        long currentCounter = Instant.now().getEpochSecond() / 30L;
        return code.equals(generateTotp(secret, currentCounter - 1))
                || code.equals(generateTotp(secret, currentCounter))
                || code.equals(generateTotp(secret, currentCounter + 1));
    }

    private String generateTotp(String secret, long counter) {
        try {
            byte[] key = decodeBase32(secret);
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
            return "";
        }
    }

    private String encodeBase32(byte[] bytes) {
        StringBuilder encoded = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte value : bytes) {
            buffer = (buffer << 8) | (value & 0xff);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                encoded.append(BASE32_ALPHABET.charAt((buffer >> (bitsLeft - 5)) & 31));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            encoded.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 31));
        }
        return encoded.toString();
    }

    private byte[] decodeBase32(String value) {
        int buffer = 0;
        int bitsLeft = 0;
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        for (char character : value.toUpperCase(Locale.ROOT).toCharArray()) {
            if (character == '=') {
                break;
            }
            int index = BASE32_ALPHABET.indexOf(character);
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
}
