package id.ac.ui.cs.advprog.bidmartauthservice.repository;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmail(String email);
}