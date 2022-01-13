package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.KeyEnvelope;
import io.blindnet.blindnet.internal.EncryptionService;
import io.blindnet.blindnet.internal.KeyFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import javax.crypto.SecretKey;
import java.security.KeyPair;

import static io.blindnet.blindnet.internal.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class KeyEnvelopeServiceTest extends AbstractTest {

    private KeyEnvelopeService keyEnvelopeService;
    private EncryptionService encryptionService;

    private KeyPair signingKeyPair;
    private KeyPair encryptionKeyPair;
    private SecretKey generatedSecretKey;

    @Before
    public void setUp() {
        keyEnvelopeService = new KeyEnvelopeService();
        KeyFactory keyFactory = new KeyFactory();
        encryptionService = new EncryptionService(keyFactory);

        signingKeyPair = keyFactory.generateEd25519KeyPair();
        encryptionKeyPair = keyFactory.generateRSAKeyPair();
        generatedSecretKey = keyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);
    }

    @Test
    @DisplayName("Test key envelope creation.")
    public void testKeyEnvelopeCreation() {
        KeyEnvelope keyEnvelope = keyEnvelopeService.create(generatedSecretKey,
                encryptionKeyPair.getPublic(),
                signingKeyPair.getPrivate(),
                "123",
                "456",
                "789");

        assertNotNull(keyEnvelope);
        assertNotNull(keyEnvelope.getEnvelopeID());
        assertNotNull(keyEnvelope.getEnvelopeSignature());
        assertNotNull(keyEnvelope.getEnvelopeVersion());
        assertNotNull(keyEnvelope.getKeyOwnerID());
        assertNotNull(keyEnvelope.getRecipientID());
        assertNotNull(keyEnvelope.getSenderID());
        assertNotNull(keyEnvelope.getEncryptedSymmetricKey());
    }

    @Test
    @DisplayName("Test key envelope signature verification")
    public void testKeyEnvelopeSignatureVerification() {
        KeyEnvelope signedKeyEnvelope = keyEnvelopeService.create(generatedSecretKey,
                encryptionKeyPair.getPublic(),
                signingKeyPair.getPrivate(),
                "123",
                "456",
                "789");

        KeyEnvelope keyEnvelope = new KeyEnvelope.Builder(signedKeyEnvelope.getEnvelopeID())
                .withVersion("1.0")
                .withEncryptedSymmetricKey(signedKeyEnvelope.getEncryptedSymmetricKey())
                .withKeyOwnerID("123")
                .withRecipientID("456")
                .withSenderID("789")
                .timestamp(signedKeyEnvelope.getTimestamp())
                .build();

        boolean verified = keyEnvelopeService.verify(keyEnvelope,
                signedKeyEnvelope.getEnvelopeSignature(),
                signingKeyPair.getPublic());

        assertTrue(verified);
    }

}
