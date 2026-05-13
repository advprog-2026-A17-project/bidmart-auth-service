package id.ac.ui.cs.advprog.bidmartauthservice.dto;

public record AuthPolicyDiagnosticsResponse(
        int concurrentSessionLimit,
        int rateLimitMaxAttempts,
        long rateLimitWindowSeconds
) {
}
