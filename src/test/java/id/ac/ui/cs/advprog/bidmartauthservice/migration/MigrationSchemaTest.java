package id.ac.ui.cs.advprog.bidmartauthservice.migration;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class MigrationSchemaTest {

    @Test
    void migrationsShouldCreateUsersBeforeRoleMappings() throws IOException {
        String v1 = Files.readString(Path.of("src/main/resources/db/migration/V1__initial_user_schema.sql"));
        String v2 = Files.readString(Path.of("src/main/resources/db/migration/V2__identity_management_schema.sql"));
        String v7 = Files.readString(Path.of("src/main/resources/db/migration/V7__drop_legacy_role_column.sql"));
        String v9 = Files.readString(Path.of("src/main/resources/db/migration/V9__seed_default_roles.sql"));
        String v11 = Files.readString(Path.of("src/main/resources/db/migration/V11__auth_wallet_provisioning_outbox.sql"));

        assertTrue(v1.toLowerCase().contains("create table users"),
                "V1 should define users table");
        assertTrue(v2.toLowerCase().contains("create table roles"),
                "V2 should define roles table");
        assertTrue(v2.toLowerCase().contains("create table user_roles"),
                "V2 should define user_roles mapping table");
        assertTrue(v1.toLowerCase().contains(" role varchar"),
                "V1 must keep original legacy role column for Flyway checksum stability");
        assertFalse(v2.toLowerCase().contains(" role varchar"),
                "V2 should not contain legacy role column on users table");
        assertTrue(v7.toLowerCase().contains("drop column if exists role"),
                "V7 should drop legacy role column from users table");
        assertTrue(v9.contains("BUYER"), "V9 should seed BUYER role");
        assertTrue(v9.contains("SELLER"), "V9 should seed SELLER role");
        assertTrue(v11.toLowerCase().contains("create table auth_outbox_events"),
                "V11 should define auth outbox table");
        assertTrue(v11.contains("idx_auth_outbox_status_next_attempt"),
                "V11 should index status + next_attempt_at for publisher polling");
    }
}
