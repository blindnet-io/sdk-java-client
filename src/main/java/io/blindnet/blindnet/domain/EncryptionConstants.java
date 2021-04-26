package io.blindnet.blindnet.domain;

public class EncryptionConstants {

    public static final String BC_PROVIDER = "BC";

    public static final String RSA_ALGORITHM = "RSA";
    public static final int RSA_KEY_SIZE_4096 = 4096;

    public static final String AES_ALGORITHM = "AES";
    public static final String AES_GCM_NO_PADDING_ALGORITHM = "AES/GCM/NoPadding";
    public static final String NONCE_IV_ALGORITHM = "NonceAndIV";
    public static final String PBKDF_SHA256 = "PBKDF2WithHmacSHA256";

    public static final int AES_KEY_SIZE = 256;
    public static final int AES_KEY_ITERATION_COUNT = 65536;
    // todo check these 2
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_T_LENGTH = 128;
    public static final int SALT_LENGTH = 16;

    public static final String ECDSA_ALGORITHM = "ECDSA";
    public static final String SECRP_256_R_CURVE = "secp256r1";

    public static final String SHA_256_ECDSA_ALGORITHM = "SHA256withECDSA";

}
