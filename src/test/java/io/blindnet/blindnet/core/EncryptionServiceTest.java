package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import io.blindnet.blindnet.domain.SymmetricJwk;
import io.blindnet.blindnet.exception.EncryptionException;
import io.blindnet.blindnet.exception.KeyEncryptionException;
import io.blindnet.blindnet.exception.KeyGenerationException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import javax.crypto.SecretKey;

import java.io.*;
import java.security.KeyPair;
import java.util.Map;
import java.util.UUID;

import static io.blindnet.blindnet.core.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.*;

public class EncryptionServiceTest extends AbstractTest {

    private EncryptionService encryptionService;
    private KeyFactory keyFactory;
    private SecretKey secretKey;
    private KeyPair encryptionKeyPair;
    private Map<String, Object> metadata;
    private String data;

    @Before
    public void setUp() {
        keyFactory = new KeyFactory();
        encryptionService = new EncryptionService(keyFactory);
        secretKey = keyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);
        encryptionKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        metadata.put("metadatakey", "metadatavalue");
        data = "random data";
    }

    @Test
    @DisplayName("Test Encryption of message using byte array to represent message data.")
    public void testEncryptMessageWithByteArrays() {
        MessageArrayWrapper messageWrapper = new MessageArrayWrapper(metadata, data.getBytes());
        byte[] encryptedData = encryptionService.encryptMessage(secretKey, messageWrapper);

        MessageArrayWrapper decryptedMessageWrapper = encryptionService.decryptMessage(secretKey, encryptedData);

        assertNotNull(decryptedMessageWrapper);
        assertNotNull(decryptedMessageWrapper.getMetadata());
        assertNotNull(decryptedMessageWrapper.getData());
        assertArrayEquals(decryptedMessageWrapper.getMetadata().values().toArray(), metadata.values().toArray());
        assertArrayEquals(messageWrapper.getData(), decryptedMessageWrapper.getData());
    }

    @Test
    @DisplayName("Test Encryption of message using input stream to represent message data.")
    public void testEncryptMessageWithStreams() throws IOException {
        ByteArrayInputStream input = new ByteArrayInputStream(data.getBytes());
        InputStream inputStream = encryptionService.encryptMessage(secretKey, new MessageStreamWrapper(metadata, input));
        assertNotNull(inputStream);

        MessageStreamWrapper result = encryptionService.decryptMessage(secretKey, inputStream);

        assertNotNull(result);
        assertNotNull(result.getMetadata());
        assertNotNull(result.getData());
        assertArrayEquals(result.getMetadata().values().toArray(), metadata.values().toArray());
        assertArrayEquals(data.getBytes(), result.getData().readAllBytes());
    }

    @Test
    @DisplayName("Test encrypting of secret key.")
    public void testEncryptSecretKey() {
        KeyPair encryptionKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);

        byte[] encrypted = encryptionService.encrypt(encryptionKeyPair.getPublic(),
                new JSONObject(new SymmetricJwk(secretKey)).toString().getBytes());

        assertNotNull(encrypted);
    }

    @Test
    @DisplayName("Test decryption of secret key.")
    public void testDecryptSecretKey() {
        KeyPair encryptionKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        JSONObject secretJwkJson = new JSONObject(new SymmetricJwk(secretKey));
        byte[] encrypted = encryptionService.encrypt(encryptionKeyPair.getPublic(),
                secretJwkJson.toString().getBytes());

        byte[] decrypted = encryptionService.decrypt(encryptionKeyPair.getPrivate(), encrypted);
        assertNotNull(decrypted);
        assertEquals(new JSONObject(new String(decrypted)).toString(), secretJwkJson.toString());
    }

    @Test
    @DisplayName("Test message encryption/decryption using invalid parameters.")
    public void testInvalidMessageEncryptionParameters() {
        byte[] data = new byte[2];
        ByteArrayInputStream input = new ByteArrayInputStream(data);
        EncryptionException encryptionException = assertThrows(EncryptionException.class,
                () -> encryptionService.decryptMessage(secretKey, input));

        assertTrue(encryptionException.getMessage().contains("Error during message decryption."));
    }

    @Test
    @DisplayName("Test encryption/decryption using invalid parameters.")
    public void testInvalidEncryptionParameters() {
        KeyEncryptionException decryptionKeyEncryptionException = assertThrows(KeyEncryptionException.class,
                () -> encryptionService.decrypt(encryptionKeyPair.getPrivate(), UUID.randomUUID().toString().getBytes()));

        assertTrue(decryptionKeyEncryptionException.getMessage().contains("Error while unwrapping secret key."));

        KeyPair ed25519keyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
        KeyEncryptionException encryptionKeyEncryptionException = assertThrows(KeyEncryptionException.class,
                () -> encryptionService.encrypt(ed25519keyPair.getPublic(),
                        new JSONObject(new SymmetricJwk(secretKey)).toString().getBytes()));

         assertTrue(encryptionKeyEncryptionException.getMessage().contains("Error while wrapping secret key."));
    }

}
