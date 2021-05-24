package io.blindnet.blindnet.core;

import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.UUID;

import static io.blindnet.blindnet.core.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.*;

public class KeyStorageTest extends AbstractTest {

    private KeyStorage keyStorage;
    private KeyPair rsaKeyPair;
    private KeyPair ed25519keyPair;

    @Before
    public void setup() {
        KeyStorageConfig.INSTANCE.setup(keyFolderPath);

        keyStorage = KeyStorage.getInstance();
        KeyFactory keyFactory = new KeyFactory();
        rsaKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        ed25519keyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
    }

    @Test
    @DisplayName("Test storing of private key used for encryption.")
    public void testStoreEncryptionKey() {
        keyStorage.storeEncryptionKey(rsaKeyPair.getPrivate());
        File encryptionKeyFile = new File(
                KeyStorageConfig.INSTANCE.getKeyFolderPath() + File.pathSeparator + ENCRYPTION_PRIVATE_KEY_FILENAME);

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
    @DisplayName("Test storing of private key used for signing.")
    public void testStoreSigningKey() {
        keyStorage.storeSigningKey(ed25519keyPair.getPrivate());
        File signingKeyFile = new File(
                KeyStorageConfig.INSTANCE.getKeyFolderPath() + File.pathSeparator + SIGNING_PRIVATE_KEY_FILENAME);

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
    }

    @Test
    @DisplayName("Test storing of recipient signing public key.")
    public void testRecipientSigningPublicKey() {
        String recipientId = UUID.randomUUID().toString();
        keyStorage.storeRecipientSigningPublicKey(ed25519keyPair.getPublic(), recipientId);
        File recipientSigningPublicKeyFile = new File(
                KeyStorageConfig.INSTANCE.getKeyFolderPath() + recipientId + ".key");

        assertNotNull(recipientSigningPublicKeyFile);
        assertTrue(recipientSigningPublicKeyFile.isFile());
    }

    @Test
    @DisplayName("Test deleting folder.")
    public void testDeleteFolder() {
        assertDoesNotThrow(() -> keyStorage.deleteKeyFolder());
    }

}
