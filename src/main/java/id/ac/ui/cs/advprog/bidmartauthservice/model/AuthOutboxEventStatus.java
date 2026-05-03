package id.ac.ui.cs.advprog.bidmartauthservice.model;

public enum AuthOutboxEventStatus {
    PENDING,
    RETRY,
    PUBLISHED,
    FAILED
}
