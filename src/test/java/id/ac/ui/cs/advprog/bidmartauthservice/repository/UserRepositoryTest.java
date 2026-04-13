package id.ac.ui.cs.advprog.bidmartauthservice.repository;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@Tag("integration")
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    void testSaveAndFindByEmail() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("repo@test.com");
        user.setPassword("123");
        user.setEnabled(true);
        user.setRoles(Set.of());

        userRepository.save(user);

        Optional<User> found = userRepository.findByEmail("repo@test.com");
        assertTrue(found.isPresent());
        assertEquals("repo@test.com", found.get().getEmail());
    }
}