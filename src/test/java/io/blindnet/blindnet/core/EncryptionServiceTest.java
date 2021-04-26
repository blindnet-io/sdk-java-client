package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.MessageWrapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import javax.crypto.SecretKey;

import static io.blindnet.blindnet.domain.EncryptionConstants.AES_ALGORITHM;
import static io.blindnet.blindnet.domain.EncryptionConstants.AES_KEY_SIZE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class EncryptionServiceTest extends AbstractTest {

    private EncryptionService encryptionService;

    @Before
    public void setUp() {
        encryptionService = new EncryptionService();
    }

    @Test
    @DisplayName("Test Encryption of message.")
    public void testEncryptMessage() {
        String metadata = "random metadata";
        String data = "random data";
        SecretKey secretKey = KeyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);

        MessageWrapper messageWrapper = new MessageWrapper(metadata.getBytes(), data.getBytes());
        byte[] encryptedData = encryptionService.encryptMessage(secretKey, messageWrapper);

        MessageWrapper decryptedMessageWrapper = encryptionService.decryptMessage(secretKey, encryptedData);

        assertNotNull(decryptedMessageWrapper);
        assertNotNull(decryptedMessageWrapper.getMetadata());
        assertNotNull(decryptedMessageWrapper.getData());
        assertArrayEquals(messageWrapper.getMetadata(), decryptedMessageWrapper.getMetadata());
        assertArrayEquals(messageWrapper.getData(), decryptedMessageWrapper.getData());
    }

}
