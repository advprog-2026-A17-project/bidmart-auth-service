package id.ac.ui.cs.advprog.bidmartauthservice.docs;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class ApiContractDocsTest {

    @Test
    void apiContractShouldDocumentCoreAuthEndpoints() throws IOException {
        Path docPath = Path.of("AUTH_API_CONTRACT.md");
        assertTrue(Files.exists(docPath), "AUTH_API_CONTRACT.md must exist");
        String content = Files.readString(docPath);
        assertTrue(content.contains("/api/v1/auth/register"));
        assertTrue(content.contains("/api/v1/auth/login"));
        assertTrue(content.contains("/api/v1/auth/refresh"));
        assertTrue(content.contains("/api/v1/auth/profile"));
        assertTrue(content.contains("/api/v1/auth/oauth/login"));
        assertTrue(content.contains("/api/v1/auth/oauth/link"));
        assertTrue(content.contains("/api/v1/auth/permissions/check"));
    }
}
