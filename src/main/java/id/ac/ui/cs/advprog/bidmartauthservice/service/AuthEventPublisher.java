package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;

public interface AuthEventPublisher {
    void publishUserRegistered(User user);
    void publishEmailVerified(User user);
    void publishUserDisabled(User user);
}
