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

        assertTrue(v1.toLowerCase().contains("create table users"),
                "V1 should define users table");
        assertTrue(v2.toLowerCase().contains("create table roles"),
                "V2 should define roles table");
        assertTrue(v2.toLowerCase().contains("create table user_roles"),
                "V2 should define user_roles mapping table");
        assertFalse(v1.toLowerCase().contains(" role varchar"),
                "V1 should not contain legacy role column on users table");
        assertFalse(v2.toLowerCase().contains(" role varchar"),
                "V2 should not contain legacy role column on users table");
    }
}
