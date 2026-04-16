package id.ac.ui.cs.advprog.bidmartauthservice.service.policy;

import id.ac.ui.cs.advprog.bidmartauthservice.exception.EmailNotVerifiedException;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class DefaultLoginEligibilityPolicy implements LoginEligibilityPolicy {
    @Override
    public boolean isPasswordCheckAllowed(User user) {
        return user.isEnabled();
    }

    @Override
    public Optional<User> resolveSuccessfulLogin(User user) {
        if (!user.isEmailVerified()) {
            throw new EmailNotVerifiedException("Email not verified");
        }

        return Optional.of(user);
    }
}
