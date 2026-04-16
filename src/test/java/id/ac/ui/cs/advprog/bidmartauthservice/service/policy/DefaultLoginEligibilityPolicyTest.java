package id.ac.ui.cs.advprog.bidmartauthservice.service.policy;

import id.ac.ui.cs.advprog.bidmartauthservice.exception.EmailNotVerifiedException;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Tag("unit")
class DefaultLoginEligibilityPolicyTest {

    private final DefaultLoginEligibilityPolicy policy = new DefaultLoginEligibilityPolicy();

    @Test
    void shouldAllowPasswordCheckWhenUserEnabled() {
        User user = new User();
        user.setEnabled(true);

        assertTrue(policy.isPasswordCheckAllowed(user));
    }

    @Test
    void shouldBlockPasswordCheckWhenUserDisabled() {
        User user = new User();
        user.setEnabled(false);

        assertFalse(policy.isPasswordCheckAllowed(user));
    }

    @Test
    void shouldReturnUserOnSuccessfulLoginWhenEmailVerified() {
        User user = new User();
        user.setEmailVerified(true);

        Optional<User> result = policy.resolveSuccessfulLogin(user);

        assertTrue(result.isPresent());
        assertSame(user, result.get());
    }

    @Test
    void shouldThrowWhenResolvingSuccessfulLoginForUnverifiedEmail() {
        User user = new User();
        user.setEmailVerified(false);

        EmailNotVerifiedException exception = assertThrows(
                EmailNotVerifiedException.class,
                () -> policy.resolveSuccessfulLogin(user)
        );

        assertEquals("Email not verified", exception.getMessage());
    }
}
