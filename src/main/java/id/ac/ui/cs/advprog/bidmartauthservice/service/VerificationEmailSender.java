package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;

public interface VerificationEmailSender {
    void sendVerificationEmail(User user, String rawToken);
}
