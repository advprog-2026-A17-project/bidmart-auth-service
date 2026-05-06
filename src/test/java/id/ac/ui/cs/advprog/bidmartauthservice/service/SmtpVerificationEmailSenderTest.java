package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayOutputStream;
import java.util.Properties;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@Tag("unit")
class SmtpVerificationEmailSenderTest {

    @Mock
    private JavaMailSender mailSender;

    @Test
    void sendVerificationEmailShouldSendMessageWithVerificationLink() throws Exception {
        SmtpVerificationEmailSender sender = new SmtpVerificationEmailSender(mailSender);
        ReflectionTestUtils.setField(sender, "verificationBaseUrl", "https://app.bidmart.dev/verify-email");
        ReflectionTestUtils.setField(sender, "fromAddress", "noreply@bidmart.dev");
        when(mailSender.createMimeMessage()).thenReturn(testMessage());

        User user = User.builder()
                .id(UUID.randomUUID())
                .email("buyer@test.com")
                .build();

        sender.sendVerificationEmail(user, "raw-token-123");

        ArgumentCaptor<MimeMessage> messageCaptor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        MimeMessage message = messageCaptor.getValue();
        assertEquals("noreply@bidmart.dev", message.getFrom()[0].toString());
        assertEquals("buyer@test.com", message.getAllRecipients()[0].toString());
        assertEquals("Verify your BidMart account", message.getSubject());
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        message.writeTo(output);
        String content = output.toString();
        assertTrue(content.contains("Verify Email"));
        assertTrue(content.contains("Confirm this email address"));
        assertTrue(content.contains("https://app.bidmart.dev/verify-email?token=raw-token-123"));
    }

    @Test
    void sendVerificationEmailShouldNotPropagateExceptionOnSmtpFailure() {
        SmtpVerificationEmailSender sender = new SmtpVerificationEmailSender(mailSender);
        ReflectionTestUtils.setField(sender, "verificationBaseUrl", "https://app.bidmart.dev/verify-email");
        ReflectionTestUtils.setField(sender, "fromAddress", "noreply@bidmart.dev");
        when(mailSender.createMimeMessage()).thenReturn(testMessage());

        User user = User.builder()
                .id(UUID.randomUUID())
                .email("buyer@test.com")
                .build();

        org.mockito.Mockito.doThrow(new org.springframework.mail.MailSendException("SMTP connection failed"))
                .when(mailSender).send(org.mockito.ArgumentMatchers.any(MimeMessage.class));

        // Should NOT throw — exception is caught internally
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                () -> sender.sendVerificationEmail(user, "raw-token-123")
        );
    }

    private MimeMessage testMessage() {
        return new MimeMessage(Session.getInstance(new Properties()));
    }
}
