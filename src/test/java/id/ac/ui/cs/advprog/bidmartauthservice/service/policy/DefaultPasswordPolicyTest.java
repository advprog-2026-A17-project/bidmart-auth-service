package id.ac.ui.cs.advprog.bidmartauthservice.service.policy;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("unit")
class DefaultPasswordPolicyTest {

    private final DefaultPasswordPolicy passwordPolicy = new DefaultPasswordPolicy();

    @Test
    void validateShouldAcceptStrongPassword() {
        assertDoesNotThrow(() -> passwordPolicy.validate("StrongPass1!"));
    }

    @Test
    void validateShouldRejectPasswordWithoutMinimumLength() {
        assertThrows(IllegalArgumentException.class, () -> passwordPolicy.validate("S1!hort"));
    }

    @Test
    void validateShouldRejectPasswordWithoutUppercaseLetter() {
        assertThrows(IllegalArgumentException.class, () -> passwordPolicy.validate("strongpass1!"));
    }

    @Test
    void validateShouldRejectPasswordWithoutLowercaseLetter() {
        assertThrows(IllegalArgumentException.class, () -> passwordPolicy.validate("STRONGPASS1!"));
    }

    @Test
    void validateShouldRejectPasswordWithoutNumber() {
        assertThrows(IllegalArgumentException.class, () -> passwordPolicy.validate("StrongPass!"));
    }

    @Test
    void validateShouldRejectPasswordWithoutSymbol() {
        assertThrows(IllegalArgumentException.class, () -> passwordPolicy.validate("StrongPass1"));
    }
}
