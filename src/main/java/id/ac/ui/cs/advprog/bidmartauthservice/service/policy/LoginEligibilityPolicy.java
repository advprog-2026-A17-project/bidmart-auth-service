package id.ac.ui.cs.advprog.bidmartauthservice.service.policy;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;

import java.util.Optional;

public interface LoginEligibilityPolicy {
    boolean isPasswordCheckAllowed(User user);
    Optional<User> resolveSuccessfulLogin(User user);
}
