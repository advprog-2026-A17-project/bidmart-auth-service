package id.ac.ui.cs.advprog.bidmartauthservice.exception;

public class RateLimitExceededException extends RuntimeException {
    public RateLimitExceededException(String message) {
        super(message);
    }
}
