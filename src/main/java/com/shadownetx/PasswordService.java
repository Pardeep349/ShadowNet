package com.shadownetx;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** Password hashing at the account boundary; plaintext is never persisted. */
public final class PasswordService {
    private static final int ITERATIONS = 310_000;
    private static final int KEY_BITS = 256;
    private static final int SALT_BYTES = 16;
    private final SecureRandom random = new SecureRandom();

    public String hash(char[] password) throws GeneralSecurityException {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] derived = derive(password, salt, ITERATIONS);
        return "pbkdf2-sha256$" + ITERATIONS + "$" + Base64.getEncoder().encodeToString(salt)
                + "$" + Base64.getEncoder().encodeToString(derived);
    }

    public boolean verify(char[] password, String encoded) throws GeneralSecurityException {
        String[] fields = encoded.split("\\$", -1);
        if (fields.length != 4 || !fields[0].equals("pbkdf2-sha256")) return false;
        int rounds = Integer.parseInt(fields[1]);
        if (rounds < 100_000 || rounds > 2_000_000) return false;
        byte[] salt = Base64.getDecoder().decode(fields[2]);
        byte[] expected = Base64.getDecoder().decode(fields[3]);
        return MessageDigest.isEqual(expected, derive(password, salt, rounds));
    }

    private static byte[] derive(char[] password, byte[] salt, int rounds) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, rounds, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
}

