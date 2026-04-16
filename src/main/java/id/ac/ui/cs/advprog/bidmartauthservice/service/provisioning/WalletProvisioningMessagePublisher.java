package id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning;

public interface WalletProvisioningMessagePublisher {
    void publish(WalletProvisionRequestedEvent event);
}
