package org.owasp.webgoat.security.mfa;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple in-memory TOTP service compatible with Microsoft Authenticator.
 * Uses RFC 6238 with HMAC-SHA1, 30-second steps, 6 digits.
 */
public class MfaService {

    public static class MfaRecord {
        private final byte[] secret;
        private volatile boolean enabled;

        public MfaRecord(byte[] secret, boolean enabled) {
            this.secret = secret;
            this.enabled = enabled;
        }
        public byte[] getSecret() { return secret; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    private static final int SECRET_BYTES = 20; // 160-bit secret
    private static final int CODE_DIGITS = 6;
    private static final int TIME_STEP_SECONDS = 30;
    private static final String HMAC_ALGO = "HmacSHA1";
    private static final Base32 BASE32 = new Base32();

    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, MfaRecord> store = new ConcurrentHashMap<>();
    private final String issuer;

    public MfaService(String issuer) {
        this.issuer = issuer;
    }

    public MfaRecord initForUser(String username) {
        byte[] secret = new byte[SECRET_BYTES];
        secureRandom.nextBytes(secret);
        MfaRecord rec = new MfaRecord(secret, false);
        store.put(username, rec);
        return rec;
    }

    public MfaRecord getRecord(String username) {
        return store.get(username);
    }

    public String getBase32Secret(byte[] secret) {
        return BASE32.encodeToString(secret).replace("=", "");
    }

    public String buildOtpAuthUri(String username, byte[] secret) {
        String b32 = getBase32Secret(secret);
        // otpauth://totp/Issuer:username?secret=...&issuer=Issuer&algorithm=SHA1&digits=6&period=30
        String label = urlEncode(issuer + ":" + username);
        String params = "secret=" + b32 + "&issuer=" + urlEncode(issuer) + "&algorithm=SHA1&digits=" + CODE_DIGITS + "&period=" + TIME_STEP_SECONDS;
        return "otpauth://totp/" + label + "?" + params;
    }

    private String urlEncode(String s) {
        return s.replace(" ", "%20"); // minimal encoding for spaces; label is usually simple
    }

    public boolean verifyCode(byte[] secret, String code) {
        if (secret == null || code == null || code.length() < 6 || code.length() > 8) return false;
        long timeWindow = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
        // allow small time drift: current window and +/-1
        for (long offset = -1; offset <= 1; offset++) {
            String expected = generateTotp(secret, timeWindow + offset, CODE_DIGITS);
            if (Objects.equals(expected, code)) return true;
        }
        return false;
    }

    private String generateTotp(byte[] key, long timeWindow, int digits) {
        try {
            byte[] counter = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(timeWindow).array();
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            byte[] hmac = mac.doFinal(counter);

            int offset = hmac[hmac.length - 1] & 0x0F;
            int binary = ((hmac[offset] & 0x7f) << 24) |
                    ((hmac[offset + 1] & 0xff) << 16) |
                    ((hmac[offset + 2] & 0xff) << 8) |
                    (hmac[offset + 3] & 0xff);

            int otp = binary % (int) Math.pow(10, digits);
            return String.format("%0" + digits + "d", otp);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate TOTP", e);
        }
    }

    public void enable(String username) {
        MfaRecord rec = store.get(username);
        if (rec != null) rec.setEnabled(true);
    }
}
