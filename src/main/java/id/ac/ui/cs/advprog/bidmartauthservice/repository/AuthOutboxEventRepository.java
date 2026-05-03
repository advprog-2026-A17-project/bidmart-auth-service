package id.ac.ui.cs.advprog.bidmartauthservice.repository;

import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEvent;
import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEventStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface AuthOutboxEventRepository extends JpaRepository<AuthOutboxEvent, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select event
            from AuthOutboxEvent event
            where event.status in :statuses
              and event.nextAttemptAt <= :now
            order by event.createdAt asc
            """)
    List<AuthOutboxEvent> findReadyForPublish(
            @Param("statuses") Collection<AuthOutboxEventStatus> statuses,
            @Param("now") Instant now,
            Pageable pageable
    );
}
