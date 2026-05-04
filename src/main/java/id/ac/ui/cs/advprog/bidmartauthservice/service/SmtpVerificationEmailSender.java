package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@Profile("!local")
@RequiredArgsConstructor
public class SmtpVerificationEmailSender implements VerificationEmailSender {

    private final JavaMailSender mailSender;

    @Value("${app.auth.email-verification.base-url:http://localhost:3000/verify-email}")
    private String verificationBaseUrl;

    @Value("${app.auth.email-verification.from:no-reply@bidmart.local}")
    private String fromAddress;

    @Override
    public void sendVerificationEmail(User user, String rawToken) {
        String verificationLink = UriComponentsBuilder
                .fromUriString(verificationBaseUrl)
                .queryParam("token", rawToken)
                .build()
                .toUriString();

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(user.getEmail());
        message.setSubject("Verify your BidMart account");
        message.setText(
                "Hello,\n\n" +
                "Please verify your email by opening this link:\n" +
                verificationLink + "\n\n" +
                "If you did not create this account, you can ignore this message."
        );

        mailSender.send(message);
    }
}