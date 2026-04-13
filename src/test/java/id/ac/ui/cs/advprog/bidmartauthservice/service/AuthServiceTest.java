package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.RoleRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.UserRepository;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
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
        when(userRepository.save(any(User.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        User saved = authService.register(email, password, roleName);

        assertNotNull(saved);
        assertNotNull(saved.getId());
        assertEquals(email, saved.getEmail());
        assertEquals(password, saved.getPassword());
        assertTrue(saved.isEnabled());
        assertNotNull(saved.getRoles());
        assertTrue(saved.getRoles().contains(role));
        verify(userRepository).findByEmail(email);
        verify(roleRepository).findByName(roleName);
        verify(userRepository).save(any(User.class));
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
        user.setPassword(password);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        Optional<User> result = authService.login(email, password);

        assertTrue(result.isPresent());
        assertEquals(email, result.get().getEmail());
    }

    @Test
    void loginShouldReturnEmptyWhenPasswordIsInvalid() {
        String email = "find@test.com";

        User user = new User();
        user.setEmail(email);
        user.setPassword("secret");

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        Optional<User> result = authService.login(email, "wrong-password");

        assertFalse(result.isPresent());
    }

    @Test
    void loginShouldReturnEmptyWhenUserNotFound() {
        when(userRepository.findByEmail("unknown@test.com")).thenReturn(Optional.empty());

        Optional<User> result = authService.login("unknown@test.com", "secret");

        assertFalse(result.isPresent());
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
}