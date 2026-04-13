package id.ac.ui.cs.advprog.bidmartauthservice.repository;

import id.ac.ui.cs.advprog.bidmartauthservice.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenIdAndRevokedFalse(UUID tokenId);
}
