package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.KeyGenerationException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.Security;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.*;

public class KeyFactoryTest {

    private static final String INVALID_SYMMETRIC_ALGORITHM = "ASE";
    private static final String INVALID_ASYMMETRIC_ALGORITHM = "RAS";
    private static final String INVALID_PROVIDER = "CB";
    private static final String INVALID_ECDSA_CURVE = "secpp256r1";

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @Test
    @DisplayName("Test generation of secret key.")
    public void testGenerateSecretKey() {
        SecretKey aesSecretKey = KeyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE_256);
        assertNotNull(aesSecretKey);

        NullPointerException algorithmNullException = assertThrows(NullPointerException.class,
                () -> KeyFactory.generateSecretKey(null, AES_KEY_SIZE_256));
        assertTrue(algorithmNullException.getMessage().contains("Algorithm name cannot be null."));

        KeyGenerationException invalidAlgorithmKGException = assertThrows(KeyGenerationException.class,
                () -> KeyFactory.generateSecretKey(INVALID_SYMMETRIC_ALGORITHM, AES_KEY_SIZE_256));
        assertTrue(invalidAlgorithmKGException.getMessage().contains("Invalid algorithm."));
    }

    @Test
    @DisplayName("Test generation of secret key spec.")
    public void testGenerateSecretKeySpec() {
        SecretKeySpec secretKeySpec = KeyFactory.generateSecretKeySpec(AES_ALGORITHM, AES_KEY_SIZE_256);
        assertNotNull(secretKeySpec);

        NullPointerException algorithmNullException = assertThrows(NullPointerException.class,
                () -> KeyFactory.generateSecretKey(null, AES_KEY_SIZE_256));
        assertTrue(algorithmNullException.getMessage().contains("Algorithm name cannot be null."));

        KeyGenerationException invalidAlgorithmKGException = assertThrows(KeyGenerationException.class,
                () -> KeyFactory.generateSecretKey(INVALID_SYMMETRIC_ALGORITHM, AES_KEY_SIZE_256));
        assertTrue(invalidAlgorithmKGException.getMessage().contains("Invalid algorithm."));
    }

    @Test
    @DisplayName("Test generation of key pair.")
    public void testGenerateKeyPair() {
        KeyPair rsaKeyPair = KeyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        assertNotNull(rsaKeyPair);
        assertNotNull(rsaKeyPair.getPrivate());
        assertNotNull(rsaKeyPair.getPublic());

        KeyPair ecdsaKeyPair = KeyFactory.generateKeyPair(ECDSA_ALGORITHM, BC_PROVIDER, SECRP_256_R_CURVE);
        assertNotNull(ecdsaKeyPair);
        assertNotNull(ecdsaKeyPair.getPrivate());
        assertNotNull(ecdsaKeyPair.getPublic());

        NullPointerException algorithmNullException = assertThrows(NullPointerException.class,
                () -> KeyFactory.generateKeyPair(null, BC_PROVIDER, RSA_KEY_SIZE_4096));
        assertTrue(algorithmNullException.getMessage().contains("Algorithm name cannot be null."));

        NullPointerException providerNullException = assertThrows(NullPointerException.class,
                () -> KeyFactory.generateKeyPair(RSA_ALGORITHM, null, RSA_KEY_SIZE_4096));
        assertTrue(providerNullException.getMessage().contains("Provider name cannot be null."));

        KeyGenerationException invalidAlgorithmKGException = assertThrows(KeyGenerationException.class,
                () -> KeyFactory.generateKeyPair(INVALID_ASYMMETRIC_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096));
        assertTrue(invalidAlgorithmKGException.getMessage().contains("Invalid algorithm."));

        KeyGenerationException invalidProviderKGException = assertThrows(KeyGenerationException.class,
                () -> KeyFactory.generateKeyPair(RSA_ALGORITHM, INVALID_PROVIDER, RSA_KEY_SIZE_4096));
        assertTrue(invalidProviderKGException.getMessage().contains("Invalid provider."));

        KeyGenerationException invalidAlgParameterKGException = assertThrows(KeyGenerationException.class,
                () -> KeyFactory.generateKeyPair(ECDSA_ALGORITHM, BC_PROVIDER, INVALID_ECDSA_CURVE));
        assertTrue(invalidAlgParameterKGException.getMessage().contains("Invalid algorithm parameter"));
    }

}
