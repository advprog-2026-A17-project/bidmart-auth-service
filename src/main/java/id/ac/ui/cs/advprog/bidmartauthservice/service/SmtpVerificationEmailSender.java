package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;

@Component
@Profile("!local")
@RequiredArgsConstructor
public class SmtpVerificationEmailSender implements VerificationEmailSender {

    private static final Logger LOGGER = LoggerFactory.getLogger(SmtpVerificationEmailSender.class);

    private final JavaMailSender mailSender;

    @Value("${app.auth.email-verification.base-url:http://localhost:3000/verify-email}")
    private String verificationBaseUrl;

    @Value("${app.auth.email-verification.from:no-reply@bidmart.local}")
    private String fromAddress;

    @Async
    @Override
    public void sendVerificationEmail(User user, String rawToken) {
        String verificationLink = UriComponentsBuilder
                .fromUriString(verificationBaseUrl)
                .queryParam("token", rawToken)
                .build()
                .toUriString();

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(
                    message,
                    true,
                    StandardCharsets.UTF_8.name()
            );
            helper.setFrom(fromAddress);
            helper.setTo(user.getEmail());
            helper.setSubject("Verify your BidMart account");
            helper.setText(plainTextBody(verificationLink), htmlBody(user, verificationLink));
            mailSender.send(message);
            LOGGER.info("Verification email sent to {}", user.getEmail());
        } catch (Exception e) {
            LOGGER.error("Failed to send verification email to {}: {}", user.getEmail(), e.getMessage(), e);
        }
    }

    private String plainTextBody(String verificationLink) {
        return "Welcome to BidMart.\n\n"
                + "Verify your email to activate bidding, wallet, and seller features:\n"
                + verificationLink + "\n\n"
                + "This link expires soon. If you did not create this account, you can ignore this message.";
    }

    private String htmlBody(User user, String verificationLink) {
        String safeEmail = HtmlUtils.htmlEscape(user.getEmail());
        String safeLink = HtmlUtils.htmlEscape(verificationLink);
        return """
                <!doctype html>
                <html>
                <body style="margin:0;background:#f7f8fa;font-family:Inter,Segoe UI,Arial,sans-serif;color:#111820;">
                  <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="background:#f7f8fa;padding:32px 16px;">
                    <tr>
                      <td align="center">
                        <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#ffffff;border:1px solid #d9dde3;border-radius:14px;overflow:hidden;">
                          <tr>
                            <td style="padding:24px 24px 16px;border-bottom:1px solid #d9dde3;">
                              <div style="font-size:13px;font-weight:700;color:#0064d2;letter-spacing:.04em;text-transform:uppercase;">BidMart</div>
                              <h1 style="margin:8px 0 0;font-size:24px;line-height:1.25;">Verify your email</h1>
                            </td>
                          </tr>
                          <tr>
                            <td style="padding:24px;">
                              <p style="margin:0 0 14px;font-size:15px;line-height:1.6;">Hi %s,</p>
                              <p style="margin:0 0 20px;font-size:15px;line-height:1.6;color:#334155;">Confirm this email address to activate your BidMart wallet, bidding, and seller access.</p>
                              <a href="%s" style="display:inline-block;background:#0064d2;color:#ffffff;text-decoration:none;font-weight:700;border-radius:10px;padding:12px 18px;">Verify Email</a>
                              <p style="margin:22px 0 0;font-size:13px;line-height:1.6;color:#5f6b7a;">If the button does not work, paste this link into your browser:<br><a href="%s" style="color:#0064d2;">%s</a></p>
                              <p style="margin:20px 0 0;font-size:12px;line-height:1.6;color:#5f6b7a;">If you did not create this account, you can ignore this email.</p>
                            </td>
                          </tr>
                        </table>
                      </td>
                    </tr>
                  </table>
                </body>
                </html>
                """.formatted(safeEmail, safeLink, safeLink, safeLink);
    }
}
