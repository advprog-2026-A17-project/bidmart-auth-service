package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@Profile("local")
public class LogVerificationEmailSender implements VerificationEmailSender {

    private static final Logger LOGGER = LoggerFactory.getLogger(LogVerificationEmailSender.class);

    @Value("${app.auth.email-verification.base-url:http://localhost/verify-email}")
    private String verificationBaseUrl;

    @Override
    public void sendVerificationEmail(User user, String rawToken) {
        String verificationLink = UriComponentsBuilder
                .fromUriString(verificationBaseUrl)
                .queryParam("token", rawToken)
                .build()
                .toUriString();

        LOGGER.info("Email verification link for {}: {}", user.getEmail(), verificationLink);
    }
}
