package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.KeyEnvelope;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
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

        signingKeyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
        encryptionKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
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
        assertNotNull(keyEnvelope.getEnvelopeId());
        assertNotNull(keyEnvelope.getKeyEnvelopeSignature());
        assertNotNull(keyEnvelope.getEnvelopeVersion());
        assertNotNull(keyEnvelope.getOwnerId());
        assertNotNull(keyEnvelope.getRecipientId());
        assertNotNull(keyEnvelope.getSenderId());
        assertNotNull(keyEnvelope.getKey());
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

        KeyEnvelope keyEnvelope = new KeyEnvelope.Builder(signedKeyEnvelope.getEnvelopeId())
                .withVersion("1.0")
                .withKey(signedKeyEnvelope.getKey())
                .withOwnerId("123")
                .withRecipientId("456")
                .withSenderId("789")
                .timestamp(signedKeyEnvelope.getTimestamp())
                .build();

        boolean verified = keyEnvelopeService.verify(keyEnvelope,
                signedKeyEnvelope.getKeyEnvelopeSignature(),
                signingKeyPair.getPublic());

        assertTrue(verified);
    }

}
