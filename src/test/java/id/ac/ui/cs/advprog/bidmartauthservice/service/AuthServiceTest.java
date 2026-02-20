package id.ac.ui.cs.advprog.bidmartauthservice.service;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.UserRepository;
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
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private AuthService authService;

    @Test
    void testRegisterUser() {
        User user = new User();
        user.setEmail("service@test.com");
        user.setPassword("pass");
        user.setRole("BUYER");

        when(userRepository.save(any(User.class))).thenReturn(user);

        User saved = authService.register(
                user.getEmail(),
                user.getPassword(),
                user.getRole()
        );

        assertNotNull(saved);
        assertEquals("service@test.com", saved.getEmail());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void testFindByEmail() {
        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setEmail("find@test.com");

        when(userRepository.findByEmail("find@test.com"))
                .thenReturn(Optional.of(user));

        Optional<User> result = authService.findByEmail("find@test.com");

        assertTrue(result.isPresent());
        assertEquals("find@test.com", result.get().getEmail());
    }
}