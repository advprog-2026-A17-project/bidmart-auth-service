package id.ac.ui.cs.advprog.bidmartauthservice.service.oauth;

import id.ac.ui.cs.advprog.bidmartauthservice.exception.InvalidOAuthTokenException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestOperations;

import java.util.Locale;
import java.util.Map;

@Component
public class GoogleOAuthIdentityVerifier implements OAuthIdentityVerifier {
    private static final String GOOGLE_PROVIDER = "google";
    private static final String GOOGLE_TOKEN_INFO_URL = "https://oauth2.googleapis.com/tokeninfo?id_token={idToken}";

    private final RestOperations restOperations;
    private final String googleClientId;

    public GoogleOAuthIdentityVerifier(
            RestOperations restOperations,
            @Value("${oauth.google.client-id:}") String googleClientId
    ) {
        this.restOperations = restOperations;
        this.googleClientId = googleClientId;
    }

    @Override
    public boolean supports(String provider) {
        return provider != null && GOOGLE_PROVIDER.equals(provider.toLowerCase(Locale.ROOT));
    }

    @Override
    public OAuthIdentity verify(String idToken) {
        if (googleClientId == null || googleClientId.isBlank()) {
            throw new InvalidOAuthTokenException("Google OAuth client id is not configured");
        }

        Map<String, Object> tokenInfo = fetchTokenInfo(idToken);
        String audience = requiredField(tokenInfo, "aud");
        if (!googleClientId.equals(audience)) {
            throw new InvalidOAuthTokenException("Google token audience mismatch");
        }

        String emailVerified = requiredField(tokenInfo, "email_verified");
        if (!"true".equalsIgnoreCase(emailVerified)) {
            throw new InvalidOAuthTokenException("Google email is not verified");
        }

        String email = requiredField(tokenInfo, "email");
        String displayName = optionalField(tokenInfo, "name");

        return new OAuthIdentity(
                requiredField(tokenInfo, "sub"),
                email,
                (displayName == null || displayName.isBlank()) ? email : displayName,
                optionalField(tokenInfo, "picture")
        );
    }

    private Map<String, Object> fetchTokenInfo(String idToken) {
        try {
            Map<String, Object> tokenInfo = restOperations.getForObject(
                    GOOGLE_TOKEN_INFO_URL,
                    Map.class,
                    idToken
            );
            if (tokenInfo == null) {
                throw new InvalidOAuthTokenException("Invalid Google ID token");
            }
            return tokenInfo;
        } catch (RestClientResponseException exception) {
            HttpStatusCode statusCode = exception.getStatusCode();
            if (statusCode.is4xxClientError()) {
                throw new InvalidOAuthTokenException("Invalid Google ID token");
            }
            throw new InvalidOAuthTokenException("Unable to validate Google ID token");
        } catch (ResourceAccessException exception) {
            throw new InvalidOAuthTokenException("Unable to reach Google OAuth provider");
        }
    }

    private String requiredField(Map<String, Object> tokenInfo, String fieldName) {
        String value = optionalField(tokenInfo, fieldName);
        if (value == null || value.isBlank()) {
            throw new InvalidOAuthTokenException("Invalid Google ID token");
        }
        return value;
    }

    private String optionalField(Map<String, Object> tokenInfo, String fieldName) {
        Object rawValue = tokenInfo.get(fieldName);
        if (rawValue == null) {
            return null;
        }

        String value = String.valueOf(rawValue).trim();
        return value.isEmpty() ? null : value;
    }
}
