package id.ac.ui.cs.advprog.bidmartauthservice.model;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@Tag("unit")
class UserTest {

    @Test
    void userSettersAndGettersShouldWork() {
        String id = UUID.randomUUID().toString();

        User user = new User();
        user.setId(id);
        user.setEmail("test@mail.com");
        user.setPassword("password123");
        user.setRole("ADMIN");
        user.setEnabled(true);

        assertEquals(id, user.getId());
        assertEquals("test@mail.com", user.getEmail());
        assertEquals("password123", user.getPassword());
        assertEquals("ADMIN", user.getRole());
        assertTrue(user.isEnabled());
    }

    @Test
    void userBuilderShouldInitializeFields() {
        User user = User.builder()
                .email("builder@mail.com")
                .password("builderpass")
                .role("BUYER")
                .enabled(true)
                .build();

        assertEquals("builder@mail.com", user.getEmail());
        assertEquals("builderpass", user.getPassword());
        assertEquals("BUYER", user.getRole());
        assertTrue(user.isEnabled());
    }
}