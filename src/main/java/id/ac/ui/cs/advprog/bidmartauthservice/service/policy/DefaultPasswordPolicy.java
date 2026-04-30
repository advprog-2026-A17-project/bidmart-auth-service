package id.ac.ui.cs.advprog.bidmartauthservice.service.policy;

import org.springframework.stereotype.Component;

@Component
public class DefaultPasswordPolicy implements PasswordPolicy {

    private static final int MINIMUM_LENGTH = 8;

    @Override
    public void validate(String password) {
        if (password == null
                || password.length() < MINIMUM_LENGTH
                || password.chars().noneMatch(Character::isUpperCase)
                || password.chars().noneMatch(Character::isLowerCase)
                || password.chars().noneMatch(Character::isDigit)
                || password.chars().noneMatch(this::isSymbol)) {
            throw new IllegalArgumentException("Password does not meet policy");
        }
    }

    private boolean isSymbol(int character) {
        return !Character.isLetterOrDigit(character) && !Character.isWhitespace(character);
    }
}
