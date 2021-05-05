package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.KeyStorageException;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import java.io.File;
import java.security.KeyPair;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class KeyStorageTest extends AbstractTest {

    private static final String invalidFilePath = "test/fp.pem";

    private KeyStorage keyStorage;
    private KeyPair keyPair;

    @Before
    public void setup() {
        keyStorage = KeyStorage.getInstance();
        keyPair = new KeyFactory().generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
    }

    @Test
    @DisplayName("Test storing of private key used for encryption.")
    public void testStoreEncryptionKey() {
        keyStorage.storeEncryptionKey(keyPair.getPrivate());
        File encryptionKeyFile = new File(KeyStorageConfig.INSTANCE.getEncryptionPrivateKeyPath());
        assertTrue(encryptionKeyFile.isFile());

        NullPointerException pkNullException = assertThrows(NullPointerException.class,
                () -> keyStorage.storeEncryptionKey(null));
        assertTrue(pkNullException.getMessage().contains("Encryption private key cannot be null."));
    }

    @Test
    @DisplayName("Test storing of private key used for signing.")
    public void testStoreSigningKey() {
        keyStorage.storeSigningKey(keyPair.getPrivate());
        File signingKeyFile = new File(KeyStorageConfig.INSTANCE.getSigningPrivateKeyPath());
        assertTrue(signingKeyFile.isFile());

        NullPointerException pkNullException = assertThrows(NullPointerException.class,
                () -> keyStorage.storeSigningKey(null));
        assertTrue(pkNullException.getMessage().contains("Signing private key cannot be null."));
    }

    @Test
    @DisplayName("Test configuring key storage with null filepath values.")
    public void testNullPathValuesOfKeyStorageConfiguration() {
        NullPointerException encryptionPKNullException = assertThrows(NullPointerException.class,
                () -> KeyStorageConfig.INSTANCE.setup(null ,"random_string"));
        assertTrue(encryptionPKNullException.getMessage().contains("Encryption key filepath cannot be null."));

        NullPointerException signingPKNullException = assertThrows(NullPointerException.class,
                () -> KeyStorageConfig.INSTANCE.setup("random_string" ,null));
        assertTrue(signingPKNullException.getMessage().contains("Signing key filepath cannot be null."));
    }

    @Test
    @DisplayName("Test configuring key storage with invalid filepath values.")
    public void testInvalidFilepathValuesOfKeyStorageConfiguration() {
        KeyStorageConfig.INSTANCE.setup(invalidFilePath, signingKeyFilePath);

        KeyStorageException invalidEncryptionPKeyFilepath = assertThrows(KeyStorageException.class,
                () -> keyStorage.storeEncryptionKey(keyPair.getPrivate()));
        assertTrue(invalidEncryptionPKeyFilepath.getMessage().contains("IO Error writing a private key to a file."));

        KeyStorageConfig.INSTANCE.setup(encryptionKeyFilePath, invalidFilePath);
        KeyStorageException invalidSigningPKeyFilepath = assertThrows(KeyStorageException.class,
                () -> keyStorage.storeSigningKey(keyPair.getPrivate()));
        assertTrue(invalidSigningPKeyFilepath.getMessage().contains("IO Error writing a private key to a file."));
    }

}
