package id.ac.ui.cs.advprog.bidmartauthservice.dto;

public record RegisterRequest(
        String email,
        String password,
        String role
) {}