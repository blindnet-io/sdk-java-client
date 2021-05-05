package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.KeyGenerationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.util.Base64;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.*;

public class KeyFactoryTest extends AbstractTest {

    private static final String INVALID_SYMMETRIC_ALGORITHM = "ASE";
    private static final String INVALID_ASYMMETRIC_ALGORITHM = "RAS";
    private static final String INVALID_PROVIDER = "CB";
    private static final String INVALID_ECDSA_CURVE = "secpp256r1";

    private KeyFactory keyFactory;

    @Before
    public void setup() {
        keyFactory = new KeyFactory();
    }

    @Test
    @DisplayName("Test generation of secret key.")
    public void testGenerateSecretKey() {
        SecretKey aesSecretKey = keyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);
        assertNotNull(aesSecretKey);

        NullPointerException algorithmNullException = assertThrows(NullPointerException.class,
                () -> keyFactory.generateSecretKey(null, AES_KEY_SIZE));
        assertTrue(algorithmNullException.getMessage().contains("Algorithm name cannot be null."));

        KeyGenerationException invalidAlgorithmKGException = assertThrows(KeyGenerationException.class,
                () -> keyFactory.generateSecretKey(INVALID_SYMMETRIC_ALGORITHM, AES_KEY_SIZE));
        assertTrue(invalidAlgorithmKGException.getMessage().contains("Invalid algorithm."));
    }

    @Test
    @DisplayName("Test generation of secret key spec.")
    public void testGenerateSecretKeySpec() {
        SecretKeySpec secretKeySpec = keyFactory.generateSecretKeySpec(AES_ALGORITHM, AES_KEY_SIZE);
        assertNotNull(secretKeySpec);

        NullPointerException algorithmNullException = assertThrows(NullPointerException.class,
                () -> keyFactory.generateSecretKey(null, AES_KEY_SIZE));
        assertTrue(algorithmNullException.getMessage().contains("Algorithm name cannot be null."));

        KeyGenerationException invalidAlgorithmKGException = assertThrows(KeyGenerationException.class,
                () -> keyFactory.generateSecretKey(INVALID_SYMMETRIC_ALGORITHM, AES_KEY_SIZE));
        assertTrue(invalidAlgorithmKGException.getMessage().contains("Invalid algorithm."));
    }

    @Test
    @DisplayName("Test generation of key pair.")
    public void testGenerateKeyPair() {
        KeyPair rsaKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        // todo remove print
        System.out.println("RSA public key: ");
        System.out.println(Base64.getUrlEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
        assertNotNull(rsaKeyPair);
        assertNotNull(rsaKeyPair.getPrivate());
        assertNotNull(rsaKeyPair.getPublic());

        KeyPair ecdsaKeyPair = keyFactory.generateKeyPair(ECDSA_ALGORITHM, BC_PROVIDER, SECRP_256_R_CURVE);
        // todo remove print
        System.out.println("ECDSA public key: ");
        System.out.println(Base64.getUrlEncoder().encodeToString(ecdsaKeyPair.getPublic().getEncoded()));
        System.out.println("Type of key: " + ecdsaKeyPair.getPrivate().getClass());
        assertNotNull(ecdsaKeyPair);
        assertNotNull(ecdsaKeyPair.getPrivate());
        assertNotNull(ecdsaKeyPair.getPublic());

        NullPointerException algorithmNullException = assertThrows(NullPointerException.class,
                () -> keyFactory.generateKeyPair(null, BC_PROVIDER, RSA_KEY_SIZE_4096));
        assertTrue(algorithmNullException.getMessage().contains("Algorithm name cannot be null."));

        NullPointerException providerNullException = assertThrows(NullPointerException.class,
                () -> keyFactory.generateKeyPair(RSA_ALGORITHM, null, RSA_KEY_SIZE_4096));
        assertTrue(providerNullException.getMessage().contains("Provider name cannot be null."));

        KeyGenerationException invalidAlgorithmKGException = assertThrows(KeyGenerationException.class,
                () -> keyFactory.generateKeyPair(INVALID_ASYMMETRIC_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096));
        assertTrue(invalidAlgorithmKGException.getMessage().contains("Invalid algorithm."));

        KeyGenerationException invalidProviderKGException = assertThrows(KeyGenerationException.class,
                () -> keyFactory.generateKeyPair(RSA_ALGORITHM, INVALID_PROVIDER, RSA_KEY_SIZE_4096));
        assertTrue(invalidProviderKGException.getMessage().contains("Invalid provider."));

        KeyGenerationException invalidAlgParameterKGException = assertThrows(KeyGenerationException.class,
                () -> keyFactory.generateKeyPair(ECDSA_ALGORITHM, BC_PROVIDER, INVALID_ECDSA_CURVE));
        assertTrue(invalidAlgParameterKGException.getMessage().contains("Invalid algorithm parameter"));
    }

}
