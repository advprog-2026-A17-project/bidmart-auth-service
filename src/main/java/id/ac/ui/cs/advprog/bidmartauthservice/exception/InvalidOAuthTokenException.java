package id.ac.ui.cs.advprog.bidmartauthservice.exception;

public class InvalidOAuthTokenException extends RuntimeException {
    public InvalidOAuthTokenException(String message) {
        super(message);
    }
}
