package id.ac.ui.cs.advprog.bidmartauthservice.model;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@Tag("unit")
class UserTest {

    @Test
    void userSettersAndGettersShouldWork() {
        UUID id = UUID.randomUUID();
        Role adminRole = Role.builder().id(UUID.randomUUID()).name("ADMIN").build();

        User user = new User();
        user.setId(id);
        user.setEmail("test@mail.com");
        user.setPassword("password123");
        user.setEnabled(true);
        user.setRoles(Set.of(adminRole));

        assertEquals(id, user.getId());
        assertEquals("test@mail.com", user.getEmail());
        assertEquals("password123", user.getPassword());
        assertEquals("ADMIN", user.getRoles().iterator().next().getName());
        assertTrue(user.isEnabled());
    }

    @Test
    void userBuilderShouldInitializeFields() {
        Role buyerRole = Role.builder().id(UUID.randomUUID()).name("BUYER").build();

        User user = User.builder()
                .email("builder@mail.com")
                .password("builderpass")
                .enabled(true)
                .roles(Set.of(buyerRole))
                .build();

        assertEquals("builder@mail.com", user.getEmail());
        assertEquals("builderpass", user.getPassword());
        assertEquals("BUYER", user.getRoles().iterator().next().getName());
        assertTrue(user.isEnabled());
    }
}