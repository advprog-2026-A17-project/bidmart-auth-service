package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.exception.InvalidTwoFactorChallengeException;
import id.ac.ui.cs.advprog.bidmartauthservice.model.TwoFactorChallenge;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.TwoFactorChallengeRepository;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;

@Service
public class TwoFactorTotpService {
    private static final String TOTP_ISSUER = "BidMart";
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final TwoFactorChallengeRepository challengeRepository;

    public TwoFactorTotpService(TwoFactorChallengeRepository challengeRepository) {
        this.challengeRepository = challengeRepository;
    }

    public void verifySetupChallenge(String challengeId, String code) {
        TwoFactorChallenge challenge = challengeRepository.findById(java.util.UUID.fromString(challengeId))
                .orElseThrow(() -> new InvalidTwoFactorChallengeException("Challenge not found or already completed."));

        if (Instant.now().isAfter(challenge.getExpiresAt())) {
            challengeRepository.delete(challenge);
            throw new InvalidTwoFactorChallengeException("Setup session expired. Please click 'Set Up 2FA' to generate a new QR code.");
        }

        if (!isCodeValid(challenge.getSecret(), code)) {
            throw new InvalidTwoFactorChallengeException("Invalid 2FA code.");
        }
    }

    public String generateSecret() {
        byte[] randomBytes = new byte[20];
        SECURE_RANDOM.nextBytes(randomBytes);
        return encodeBase32(randomBytes);
    }

    public String buildOtpAuthUrl(String email, String secret) {
        String issuer = URLEncoder.encode(TOTP_ISSUER, StandardCharsets.UTF_8);
        return "otpauth://totp/" + TOTP_ISSUER + ":" + email + "?secret=" + secret + "&issuer=" + issuer;
    }

    public boolean isCodeValid(String secret, String code) {
        if (secret == null || code == null || !code.matches("\\d{6}")) {
            return false;
        }
        long currentCounter = Instant.now().getEpochSecond() / 30L;
        return code.equals(generateTotp(secret, currentCounter - 1))
                || code.equals(generateTotp(secret, currentCounter))
                || code.equals(generateTotp(secret, currentCounter + 1));
    }

    private String generateTotp(String secret, long counter) {
        try {
            byte[] key = decodeBase32(secret);
            byte[] counterBytes = ByteBuffer.allocate(Long.BYTES).putLong(counter).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(counterBytes);
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);
            return String.format("%06d", binary % 1_000_000);
        } catch (Exception exception) {
            return "";
        }
    }

    private String encodeBase32(byte[] bytes) {
        StringBuilder encoded = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte value : bytes) {
            buffer = (buffer << 8) | (value & 0xff);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                encoded.append(BASE32_ALPHABET.charAt((buffer >> (bitsLeft - 5)) & 31));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            encoded.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 31));
        }
        return encoded.toString();
    }

    private byte[] decodeBase32(String value) {
        int buffer = 0;
        int bitsLeft = 0;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (char character : value.toUpperCase(Locale.ROOT).toCharArray()) {
            if (character == '=') {
                break;
            }
            int index = BASE32_ALPHABET.indexOf(character);
            if (index < 0) {
                throw new IllegalArgumentException("Invalid base32 secret");
            }
            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                output.write((buffer >> (bitsLeft - 8)) & 0xff);
                bitsLeft -= 8;
            }
        }
        return output.toByteArray();
    }
}