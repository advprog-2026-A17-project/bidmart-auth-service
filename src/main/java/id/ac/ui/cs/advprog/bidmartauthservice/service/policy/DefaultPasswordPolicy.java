package id.ac.ui.cs.advprog.bidmartauthservice.service.policy;

import org.springframework.stereotype.Component;

@Component
public class DefaultPasswordPolicy implements PasswordPolicy {

    private static final int MINIMUM_LENGTH = 8;

    @Override
    public void validate(String password) {
        if (password == null) {
            throw new IllegalArgumentException("Password is required");
        }
        if (password.length() < MINIMUM_LENGTH) {
            throw new IllegalArgumentException("Password must be at least " + MINIMUM_LENGTH + " characters long");
        }
        if (password.chars().noneMatch(Character::isUpperCase)) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        }
        if (password.chars().noneMatch(Character::isLowerCase)) {
            throw new IllegalArgumentException("Password must contain at least one lowercase letter");
        }
        if (password.chars().noneMatch(Character::isDigit)) {
            throw new IllegalArgumentException("Password must contain at least one digit");
        }
        if (password.chars().noneMatch(this::isSymbol)) {
            throw new IllegalArgumentException("Password must contain at least one special character");
        }
    }

    private boolean isSymbol(int character) {
        return !Character.isLetterOrDigit(character) && !Character.isWhitespace(character);
    }
}
