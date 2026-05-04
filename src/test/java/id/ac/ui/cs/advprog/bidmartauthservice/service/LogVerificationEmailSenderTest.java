package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, OutputCaptureExtension.class})
class LogVerificationEmailSenderTest {

    @InjectMocks
    private LogVerificationEmailSender logVerificationEmailSender;

    @Mock
    private User user;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(
                logVerificationEmailSender, 
                "verificationBaseUrl", 
                "http://localhost:3000/verify-email"
        );
    }

    @Test
    void testSendVerificationEmail(CapturedOutput output) {
        String testEmail = "test@example.com";
        String testToken = "sample-token-123";
        when(user.getEmail()).thenReturn(testEmail);

        logVerificationEmailSender.sendVerificationEmail(user, testToken);

        assertTrue(output.getOut().contains("Email verification link for " + testEmail));
        assertTrue(output.getOut().contains("token=" + testToken));
        assertTrue(output.getOut().contains("http://localhost/verify-email"));
    }
}