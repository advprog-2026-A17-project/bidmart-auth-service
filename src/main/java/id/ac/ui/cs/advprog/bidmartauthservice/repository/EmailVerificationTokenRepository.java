package id.ac.ui.cs.advprog.bidmartauthservice.repository;

import id.ac.ui.cs.advprog.bidmartauthservice.model.EmailVerificationToken;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, UUID> {
    Optional<EmailVerificationToken> findByTokenHashAndUsedAtIsNull(String tokenHash);
    List<EmailVerificationToken> findByUserAndUsedAtIsNull(User user);
    Optional<EmailVerificationToken> findFirstByUserAndUsedAtIsNullOrderByCreatedAtDesc(User user);
}
