package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.KeyConstructionException;
import io.blindnet.blindnet.exception.KeyGenerationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.*;

public class KeyFactoryTest extends AbstractTest {

    private static final String INVALID_NONCE_IV_ALGORITHM = "NceAndIV";
    private static final String INVALID_SYMMETRIC_ALGORITHM = "ASE";
    private static final String INVALID_PROVIDER = "CBC";
    private static final String INVALID_ASYMMETRIC_ALGORITHM = "RAS";
    private static final String INVALID_PBKDF_SHA256 = "PBKDFFF_SHA256";

    private KeyFactory keyFactory;

    @Before
    public void setup() {
        keyFactory = new KeyFactory();
    }

    @Test
    @DisplayName("Test generation of random.")
    public void testGenerateRandom() {
        byte[] salt = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH);

        assertNotNull(salt);
        assertEquals(salt.length, SALT_LENGTH);

        KeyGenerationException generateRandomKGException = assertThrows(KeyGenerationException.class,
                () -> keyFactory.generateRandom(INVALID_NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH));
        assertTrue(generateRandomKGException.getMessage().contains("Error while generating secure random."));
    }

    @Test
    @DisplayName("Test generation of secret key.")
    public void testGenerateSecretKey() {
        SecretKey aesSecretKey = keyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);

        assertNotNull(aesSecretKey);
        assertEquals(aesSecretKey.getAlgorithm(), AES_ALGORITHM);

        KeyGenerationException generateSecretKGException = assertThrows(KeyGenerationException.class,
                () -> keyFactory.generateSecretKey(INVALID_SYMMETRIC_ALGORITHM, AES_KEY_SIZE));
        assertTrue(generateSecretKGException.getMessage().contains("Invalid algorithm."));
    }

    @Test
    @DisplayName("Test generation of RSA key pair.")
    public void testGenerateRSAKeyPair() {
        KeyPair rsaKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);

        assertNotNull(rsaKeyPair);
        assertNotNull(rsaKeyPair.getPrivate());
        assertNotNull(rsaKeyPair.getPublic());

        KeyGenerationException generateKeyPairKGException = assertThrows(KeyGenerationException.class,
                () -> keyFactory.generateKeyPair(INVALID_ASYMMETRIC_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096));
        assertTrue(generateKeyPairKGException.getMessage().contains("Invalid algorithm."));
    }

    @Test
    @DisplayName("Test generation of Ed25519 key pair.")
    public void testGenerateEd25519KeyPair() {
        KeyPair ed25519KeyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);

        assertNotNull(ed25519KeyPair);
        assertNotNull(ed25519KeyPair.getPrivate());
        assertNotNull(ed25519KeyPair.getPublic());

        KeyGenerationException generateKeyPairKGException = assertThrows(KeyGenerationException.class,
                () -> keyFactory.generateKeyPair(Ed25519_ALGORITHM, INVALID_PROVIDER, -1));
        assertTrue(generateKeyPairKGException.getMessage().contains("Invalid provider."));
    }

    @Test
    @DisplayName("Test extraction of AES key from password phrase.")
    public void testExtractAESKeyFromPassword() {
        byte[] salt = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH);

        SecretKey secretKey = keyFactory.extractAesKeyFromPassword("randompassword".toCharArray(),
                salt,
                PBKDF_SHA256);

        assertNotNull(secretKey);
        assertEquals(secretKey.getAlgorithm(), AES_ALGORITHM);

        KeyGenerationException extractAesKeyKGException = assertThrows(KeyGenerationException.class,
                () -> keyFactory.extractAesKeyFromPassword("randompassword".toCharArray(),
                        salt,
                        INVALID_PBKDF_SHA256));
        assertTrue(extractAesKeyKGException.getMessage().contains("Error while generating AES key from password."));
    }

    @Test
    @DisplayName("Test extraction of RSA public key from private key.")
    public void testExtractRsaPublicKey() {
        KeyPair rsaKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        PublicKey publicKey = keyFactory.extractRsaPublicKey(rsaKeyPair.getPrivate());

        assertNotNull(publicKey);
        assertEquals(publicKey.getAlgorithm(), RSA_ALGORITHM);
        assertEquals(Base64.getUrlEncoder().encodeToString(publicKey.getEncoded()),
                Base64.getUrlEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
    }

    @Test
    @DisplayName("Test conversion to public key object from base64 encoded data.")
    public void testConvertToPublicKey() {
        KeyPair rsaKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        String base64EncodedPublicKey = Base64.getUrlEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded());
        PublicKey publicKey = keyFactory.convertToPublicKey(base64EncodedPublicKey, RSA_ALGORITHM);

        assertNotNull(publicKey);
        assertEquals(publicKey.getAlgorithm(), RSA_ALGORITHM);
        assertEquals(Base64.getUrlEncoder().encodeToString(publicKey.getEncoded()), base64EncodedPublicKey);

        KeyConstructionException convertToPublicKeyKCException = assertThrows(KeyConstructionException.class,
                () -> keyFactory.convertToPublicKey(base64EncodedPublicKey, INVALID_ASYMMETRIC_ALGORITHM));
        assertTrue(convertToPublicKeyKCException.getMessage().contains("Error while converting public key."));
    }

    @Test
    @DisplayName("Test conversion to RSA private key object from byte array data.")
    public void testConvertToRSAPrivateKey() {
        KeyPair rsaKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        PrivateKey rsaPrivateKey = keyFactory.convertToPrivateKey(rsaKeyPair.getPrivate().getEncoded(), RSA_ALGORITHM);

        assertNotNull(rsaPrivateKey);
        assertEquals(rsaPrivateKey.getAlgorithm(), RSA_ALGORITHM);
        assertEquals(Base64.getUrlEncoder().encodeToString(rsaPrivateKey.getEncoded()),
                Base64.getUrlEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded()));

        KeyConstructionException convertToPrivateKeyKCException = assertThrows(KeyConstructionException.class,
                () -> keyFactory.convertToPrivateKey(rsaKeyPair.getPrivate().getEncoded(), INVALID_ASYMMETRIC_ALGORITHM));
        assertTrue(convertToPrivateKeyKCException.getMessage().contains("Error while converting private key."));
    }

    @Test
    @DisplayName("Test conversion to Ed25519 private key object from byte array data.")
    public void testConvertToEd25519PrivateKey() {
        KeyPair ed25519keyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
        PrivateKey ed25519PrivateKey = keyFactory.convertToPrivateKey(ed25519keyPair.getPrivate().getEncoded(), Ed25519_ALGORITHM);

        assertNotNull(ed25519PrivateKey);
        assertEquals(ed25519PrivateKey.getAlgorithm(), Ed25519_ALGORITHM);
        assertEquals(Base64.getUrlEncoder().encodeToString(ed25519PrivateKey.getEncoded()),
                Base64.getUrlEncoder().encodeToString(ed25519keyPair.getPrivate().getEncoded()));
    }

}
