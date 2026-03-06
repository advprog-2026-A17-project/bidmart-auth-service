package id.ac.ui.cs.advprog.bidmartauthservice.model;

import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role {

    @Id
    private UUID id;

    @Column(unique = true, nullable = false)
    private String name;
}