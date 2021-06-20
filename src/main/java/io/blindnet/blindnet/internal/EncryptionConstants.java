package io.blindnet.blindnet.internal;

/**
 * Provides constants that are used in encryption/decryption operations.
 */
public final class EncryptionConstants {

    private EncryptionConstants() {
    }

    public static final String ENCRYPTION_PRIVATE_KEY_FILENAME = "enc.pem";
    public static final String SIGNING_PRIVATE_KEY_FILENAME = "sign.pem";

    public static final String BC_PROVIDER = "BC";

    public static final String RSA_ALGORITHM = "RSA";
    public static final int RSA_KEY_SIZE_4096 = 4096;

    public static final String Ed25519_ALGORITHM = "Ed25519";

    public static final String AES_ALGORITHM = "AES";
    public static final String AES_GCM_NO_PADDING_ALGORITHM = "AES/GCM/NoPadding";
    public static final String NONCE_IV_ALGORITHM = "NonceAndIV";
    public static final String PBKDF_SHA256 = "PBKDF2WithHmacSHA256";

    public static final int AES_KEY_SIZE = 256;
    public static final int AES_KEY_ITERATION_COUNT = 100000;

    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_T_LENGTH = 128;
    public static final int SALT_LENGTH = 16;

}
