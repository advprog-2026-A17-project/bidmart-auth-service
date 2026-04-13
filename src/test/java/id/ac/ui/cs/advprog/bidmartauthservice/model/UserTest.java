package id.ac.ui.cs.advprog.bidmartauthservice.model;
import org.junit.jupiter.api.Test;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class UserTest {

    @Test
    void testUserCreation() {
        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setEmail("test@mail.com");
        user.setPassword("password123");
        user.setRole("ADMIN");
        user.setEnabled(true);

        assertNotNull(user.getId());
        assertEquals("test@mail.com", user.getEmail());
        assertEquals("password123", user.getPassword());
        assertEquals("ADMIN", user.getRole());
    }
}