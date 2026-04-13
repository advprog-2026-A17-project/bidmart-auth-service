package id.ac.ui.cs.advprog.bidmartauthservice.ci;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class CiWorkflowTest {

    @Test
    void ciWorkflowShouldRunIntegrationTests() throws IOException {
        String ciWorkflow = Files.readString(Path.of(".github/workflows/ci.yml"));
        assertTrue(ciWorkflow.contains("integrationTest"),
                "CI workflow must execute integrationTest task");
    }
}
