package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import javax.crypto.SecretKey;

import java.io.*;
import java.security.GeneralSecurityException;

import static io.blindnet.blindnet.domain.EncryptionConstants.AES_ALGORITHM;
import static io.blindnet.blindnet.domain.EncryptionConstants.AES_KEY_SIZE;
import static org.junit.jupiter.api.Assertions.*;

public class EncryptionServiceTest extends AbstractTest {

    private EncryptionService encryptionService;

    @Before
    public void setUp() {
        encryptionService = new EncryptionService();
    }

    @Test
    @DisplayName("Test Encryption of message using byte array to represent message data.")
    public void testEncryptMessageWithByteArrays() {
        String metadata = "random metadata";
        String data = "random data";
        SecretKey secretKey = KeyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);

        MessageArrayWrapper messageWrapper = new MessageArrayWrapper(metadata.getBytes(), data.getBytes());
        byte[] encryptedData = encryptionService.encryptMessage(secretKey, messageWrapper);

        MessageArrayWrapper decryptedMessageWrapper = encryptionService.decryptMessage(secretKey, encryptedData);

        assertNotNull(decryptedMessageWrapper);
        assertNotNull(decryptedMessageWrapper.getMetadata());
        assertNotNull(decryptedMessageWrapper.getData());
        assertArrayEquals(messageWrapper.getMetadata(), decryptedMessageWrapper.getMetadata());
        assertArrayEquals(messageWrapper.getData(), decryptedMessageWrapper.getData());
    }

    @Test
    @DisplayName("Test Encryption of message using input stream to represent message data.")
    public void testEncryptMessageWithStreams() throws IOException {
        String metadata = "random metadata";
        String data = "random data";
        SecretKey secretKey = KeyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);

        ByteArrayInputStream input = new ByteArrayInputStream(data.getBytes());
        InputStream inputStream = encryptionService.encryptMessage(secretKey, new MessageStreamWrapper(metadata.getBytes(), input));
        assertNotNull(inputStream);

        MessageStreamWrapper result = encryptionService.decryptMessage(secretKey, inputStream);

        assertNotNull(result);
        assertNotNull(result.getMetadata());
        assertNotNull(result.getData());
        assertArrayEquals(result.getMetadata(), metadata.getBytes());
        assertArrayEquals(data.getBytes(), result.getData().readAllBytes());
    }

}
