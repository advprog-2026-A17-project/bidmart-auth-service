package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.RoleRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.UserRepository;

import id.ac.ui.cs.advprog.bidmartauthservice.exception.EmailAlreadyRegisteredException;
import id.ac.ui.cs.advprog.bidmartauthservice.exception.RoleNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthEventPublisher authEventPublisher;

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
                .verificationToken(UUID.randomUUID().toString())
                .verificationTokenExpiresAt(Instant.now().plusSeconds(86400))
                .roles(Set.of(role))
                .build();

        User savedUser = userRepository.save(user);
        authEventPublisher.publishUserRegistered(savedUser);
        return savedUser;
    }

    public Optional<User> login(String email, String password) {

        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isPresent() &&
                userOpt.get().isEmailVerified() &&
                passwordEncoder.matches(password, userOpt.get().getPassword())) {

            return userOpt;
        }

        return Optional.empty();
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
        return userRepository.findByVerificationToken(token)
                .filter(user -> user.getVerificationTokenExpiresAt() != null &&
                        user.getVerificationTokenExpiresAt().isAfter(Instant.now()))
                .map(user -> {
                    user.setEmailVerified(true);
                    user.setVerificationToken(null);
                    user.setVerificationTokenExpiresAt(null);
                    userRepository.save(user);
                    authEventPublisher.publishEmailVerified(user);
                    return true;
                })
                .orElse(false);
    }

    public void resendVerification(String email) {
        userRepository.findByEmail(email)
                .filter(user -> !user.isEmailVerified())
                .ifPresent(user -> {
                    user.setVerificationToken(UUID.randomUUID().toString());
                    user.setVerificationTokenExpiresAt(Instant.now().plusSeconds(86400));
                    userRepository.save(user);
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

    public User oauthLogin(String provider, String providerUserId, String email, String displayName) {
        Optional<User> existingUser = userRepository.findByEmail(email);
        if (existingUser.isPresent()) {
            return existingUser.get();
        }

        Role buyerRole = roleRepository.findByName("BUYER")
                .orElseGet(() -> roleRepository.save(Role.builder()
                        .id(UUID.randomUUID())
                        .name("BUYER")
                        .build()));

        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                .enabled(true)
                .emailVerified(true)
                .verificationToken(null)
                .verificationTokenExpiresAt(null)
                .oauthProvider(provider)
                .oauthSubject(providerUserId)
                .displayName(displayName)
                .roles(Set.of(buyerRole))
                .build();

        return userRepository.save(user);
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
}
