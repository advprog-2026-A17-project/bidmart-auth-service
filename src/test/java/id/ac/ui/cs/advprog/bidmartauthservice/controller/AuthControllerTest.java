package id.ac.ui.cs.advprog.bidmartauthservice.controller;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.service.AuthService;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Tag("unit")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @Test
    void registerShouldReturnRegisteredUser() throws Exception {
        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setEmail("controller@test.com");
        user.setPassword("pass");
        user.setRole("BUYER");
        user.setEnabled(true);

        when(authService.register("controller@test.com", "pass", "BUYER"))
                .thenReturn(user);

        mockMvc.perform(post("/api/auth/register")
                .param("email", "controller@test.com")
                .param("password", "pass")
                .param("role", "BUYER"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("controller@test.com"))
                .andExpect(jsonPath("$.role").value("BUYER"))
                .andExpect(jsonPath("$.enabled").value(true));
    }

    @Test
    void loginShouldReturnUserWhenCredentialsValid() throws Exception {
        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setEmail("buyer@test.com");
        user.setPassword("pass");
        user.setRole("BUYER");
        user.setEnabled(true);

        when(authService.login("buyer@test.com", "pass"))
                .thenReturn(Optional.of(user));

        mockMvc.perform(post("/api/auth/login")
                .param("email", "buyer@test.com")
                .param("password", "pass"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("buyer@test.com"));
    }

    @Test
    void loginShouldReturnUnauthorizedWhenCredentialsInvalid() throws Exception {
        when(authService.login("buyer@test.com", "wrong"))
                .thenReturn(Optional.empty());

        mockMvc.perform(post("/api/auth/login")
                .param("email", "buyer@test.com")
                .param("password", "wrong"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"));
    }

    @Test
    void getUserShouldReturnUserWhenExists() throws Exception {
        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setEmail("buyer@test.com");
        user.setPassword("pass");
        user.setRole("BUYER");
        user.setEnabled(true);

        when(authService.findByEmail("buyer@test.com"))
                .thenReturn(Optional.of(user));

        mockMvc.perform(get("/api/auth/user")
                .param("email", "buyer@test.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("buyer@test.com"));
    }

    @Test
    void getUserShouldReturnNotFoundWhenMissing() throws Exception {
        when(authService.findByEmail("missing@test.com"))
                .thenReturn(Optional.empty());

        mockMvc.perform(get("/api/auth/user")
                .param("email", "missing@test.com"))
                .andExpect(status().isNotFound());
    }
}