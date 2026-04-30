package id.ac.ui.cs.advprog.bidmartauthservice.dto;

/**
 * Returned by POST /login when the user has 2FA enabled.
 * The client must present the challengeToken + TOTP code
 * to POST /2fa/login-verify to receive full access tokens.
 */
public record TwoFactorChallengeResponse(
        String challengeToken,
        boolean twoFactorRequired,
        String message
) {
    public TwoFactorChallengeResponse(String challengeToken) {
        this(challengeToken, true, "Two-factor authentication required");
    }
}
