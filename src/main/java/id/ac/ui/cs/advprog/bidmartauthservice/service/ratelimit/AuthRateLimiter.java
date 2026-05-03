package id.ac.ui.cs.advprog.bidmartauthservice.service.ratelimit;

public interface AuthRateLimiter {
    void assertAllowed(String operation, String subject);
}
