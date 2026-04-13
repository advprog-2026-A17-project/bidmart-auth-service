package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.RoleRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.UserRepository;

import id.ac.ui.cs.advprog.bidmartauthservice.exception.EmailAlreadyRegisteredException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public User register(String email, String password, String roleName) {

        // cek apakah email sudah ada
        if (userRepository.findByEmail(email).isPresent()) {
            throw new EmailAlreadyRegisteredException("Email already registered");
        }

        // cari role
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        // buat user
        User user = User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .password(passwordEncoder.encode(password))
                .enabled(true)
                .roles(Set.of(role))
                .build();

        return userRepository.save(user);
    }

    public Optional<User> login(String email, String password) {

        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isPresent() &&
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
}
