package id.ac.ui.cs.advprog.bidmartauthservice.service;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("unit")
class VerificationTokenCodecTest {

    private final VerificationTokenCodec codec = new VerificationTokenCodec();

    @Test
    void generateRawTokenShouldProduceUrlSafeValue() {
        String token = codec.generateRawToken();

        assertTrue(token.length() >= 40);
        assertTrue(token.matches("^[A-Za-z0-9_-]+$"));
    }

    @Test
    void generateRawTokenShouldProduceDifferentValues() {
        String first = codec.generateRawToken();
        String second = codec.generateRawToken();

        assertNotEquals(first, second);
    }

    @Test
    void hashTokenShouldBeDeterministicSha256Hex() {
        String hash = codec.hashToken("sample-token");

        assertEquals(64, hash.length());
        assertTrue(hash.matches("^[a-f0-9]{64}$"));
        assertEquals(hash, codec.hashToken("sample-token"));
    }
}
