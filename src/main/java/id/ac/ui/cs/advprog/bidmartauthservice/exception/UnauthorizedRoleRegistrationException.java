package id.ac.ui.cs.advprog.bidmartauthservice.exception;

public class UnauthorizedRoleRegistrationException extends RuntimeException {
    public UnauthorizedRoleRegistrationException(String message) {
        super(message);
    }
}