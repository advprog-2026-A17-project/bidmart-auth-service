package id.ac.ui.cs.advprog.bidmartauthservice.exception;

public class InvalidTwoFactorChallengeException extends RuntimeException {
    public InvalidTwoFactorChallengeException(String message) {
        super(message);
    }
}
