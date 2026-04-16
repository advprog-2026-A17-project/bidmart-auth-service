package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.model.EmailVerificationToken;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.EmailVerificationTokenRepository;
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

import java.time.Instant;
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
}
