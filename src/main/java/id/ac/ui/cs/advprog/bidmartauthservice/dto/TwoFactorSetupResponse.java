package id.ac.ui.cs.advprog.bidmartauthservice.dto;

public record TwoFactorSetupResponse(
        String secret,
        String qrCodeUrl
) {
}
