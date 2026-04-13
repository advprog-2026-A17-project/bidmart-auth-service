package id.ac.ui.cs.advprog.bidmartauthservice.docs;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class BranchSyncGuideTest {

    @Test
    void branchSyncGuideShouldDocumentSafeFastForwardFlow() throws IOException {
        Path docPath = Path.of("BRANCH_SYNC_GUIDE.md");
        assertTrue(Files.exists(docPath), "BRANCH_SYNC_GUIDE.md must exist");
        String content = Files.readString(docPath);
        assertTrue(content.contains("git fetch --all --prune"));
        assertTrue(content.contains("git pull --ff-only"));
        assertTrue(content.contains("cicd"));
        assertTrue(content.contains("staging"));
        assertTrue(content.contains("main"));
    }
}
