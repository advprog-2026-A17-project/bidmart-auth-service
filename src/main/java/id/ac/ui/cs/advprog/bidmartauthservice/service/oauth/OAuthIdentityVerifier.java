package id.ac.ui.cs.advprog.bidmartauthservice.service.oauth;

public interface OAuthIdentityVerifier {
    boolean supports(String provider);
    OAuthIdentity verify(String idToken);
}
