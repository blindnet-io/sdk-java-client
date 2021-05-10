package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.KeyStorageException;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.UUID;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.*;

public class KeyStorageTest extends AbstractTest {

    private static final String invalidFilePath = "test/fp.pem";

    private KeyStorage keyStorage;
    private KeyPair rsaKeyPair;
    private KeyPair ed25519keyPair;

    @Before
    public void setup() {
        KeyStorageConfig.INSTANCE.setup(encryptionKeyFilePath,
                signingKeyFilePath,
                recipientSigningPublicKeyFolderPath);

        keyStorage = KeyStorage.getInstance();
        KeyFactory keyFactory = new KeyFactory();
        rsaKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        ed25519keyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
    }

    @Test
    @DisplayName("Test storing of private key used for encryption.")
    public void testStoreEncryptionKey() {
        keyStorage.storeEncryptionKey(rsaKeyPair.getPrivate());
        File encryptionKeyFile = new File(KeyStorageConfig.INSTANCE.getEncryptionPrivateKeyPath());

        assertNotNull(encryptionKeyFile);
        assertTrue(encryptionKeyFile.isFile());
    }

    @Test
    @DisplayName("Test reading of private key used for encryption.")
    public void testReadEncryptionKey() {
        keyStorage.storeEncryptionKey(rsaKeyPair.getPrivate());
        PrivateKey privateKey = keyStorage.readEncryptionPrivateKey();

        assertNotNull(privateKey);
        assertEquals(privateKey.getAlgorithm(), RSA_ALGORITHM);
        assertEquals(Base64.getUrlEncoder().encodeToString(privateKey.getEncoded()),
                Base64.getUrlEncoder().encodeToString(rsaKeyPair.getPrivate().getEncoded()));
    }

    @Test
    @DisplayName("Test deletion of private key used for encryption.")
    public void testDeleteEncryptionKey() {
        keyStorage.storeEncryptionKey(rsaKeyPair.getPrivate());
        boolean deleted = keyStorage.deleteEncryptionKey();

        assertTrue(deleted);
    }

    @Test
    @DisplayName("Test storing of private key used for signing.")
    public void testStoreSigningKey() {
        keyStorage.storeSigningKey(ed25519keyPair.getPrivate());
        File signingKeyFile = new File(KeyStorageConfig.INSTANCE.getSigningPrivateKeyPath());

        assertNotNull(signingKeyFile);
        assertTrue(signingKeyFile.isFile());
    }

    @Test
    @DisplayName("Test reading of private key used for signing.")
    public void testReadSigningKey() {
        keyStorage.storeSigningKey(ed25519keyPair.getPrivate());
        PrivateKey privateKey = keyStorage.readSigningPrivateKey();

        assertNotNull(privateKey);
        assertEquals(privateKey.getAlgorithm(), Ed25519_ALGORITHM);
        assertEquals(Base64.getUrlEncoder().encodeToString(privateKey.getEncoded()),
                Base64.getUrlEncoder().encodeToString(ed25519keyPair.getPrivate().getEncoded()));


        KeyStorageConfig.INSTANCE.setup(encryptionKeyFilePath,
                "invalidkeypath",
                recipientSigningPublicKeyFolderPath);
        KeyStorageException keyStorageException = assertThrows(KeyStorageException.class,
                () -> keyStorage.readSigningPrivateKey());
        assertTrue(keyStorageException.getMessage().contains("Invalid file path while reading a private key."));
    }

    @Test
    @DisplayName("Test deletion of private key used for signing.")
    public void testDeleteSigningKey() {
        keyStorage.storeSigningKey(ed25519keyPair.getPrivate());
        boolean deleted = keyStorage.deleteSigningKey();

        assertTrue(deleted);
    }

    @Test
    @DisplayName("Test recipient signing public key.")
    public void testRecipientSigningPublicKey() {
        String recipientId = UUID.randomUUID().toString();
        keyStorage.storeRecipientSigningPublicKey(ed25519keyPair.getPublic(), recipientId);
        File recipientSigningPublicKeyFile = new File(
                KeyStorageConfig.INSTANCE.getRecipientSigningPublicKeyFolderPath() + recipientId + ".key");

        assertNotNull(recipientSigningPublicKeyFile);
        assertTrue(recipientSigningPublicKeyFile.isFile());
    }

    @Test
    @DisplayName("Test configuring key storage with invalid filepath values.")
    public void testInvalidFilepathValuesOfKeyStorageConfiguration() {
        KeyStorageConfig.INSTANCE.setup(invalidFilePath, signingKeyFilePath, "random");

        KeyStorageException invalidEncryptionPKeyFilepath = assertThrows(KeyStorageException.class,
                () -> keyStorage.storeEncryptionKey(rsaKeyPair.getPrivate()));
        assertTrue(invalidEncryptionPKeyFilepath.getMessage().contains("IO Error writing a private key to a file."));

        KeyStorageConfig.INSTANCE.setup(encryptionKeyFilePath, invalidFilePath, "random");
        KeyStorageException invalidSigningPKeyFilepath = assertThrows(KeyStorageException.class,
                () -> keyStorage.storeSigningKey(rsaKeyPair.getPrivate()));
        assertTrue(invalidSigningPKeyFilepath.getMessage().contains("IO Error writing a private key to a file."));
    }

}
