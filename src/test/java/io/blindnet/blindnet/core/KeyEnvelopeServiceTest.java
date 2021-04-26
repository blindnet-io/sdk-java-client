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
import java.util.Base64;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class KeyEnvelopeServiceTest extends AbstractTest {

    private KeyEnvelopeService keyEnvelopeService;

    @Before
    public void setUp() {
        keyEnvelopeService = new KeyEnvelopeService();
    }

    @Test
    @DisplayName("Test Key Envelope creation.")
    public void testKeyEnvelopeCreation() {

        // todo change
        // signing private key
        KeyPair signingKeyPair = KeyFactory.generateKeyPair(ECDSA_ALGORITHM, BC_PROVIDER, SECRP_256_R_CURVE);
        PrivateKey signingPrivateKey = signingKeyPair.getPrivate();
        System.out.println("Signing public key: ");
        System.out.println(Base64.getUrlEncoder().encodeToString(signingKeyPair.getPublic().getEncoded()));
        // encryption public key
        KeyPair encryptionKeyPair = KeyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        // todo this will be used => read local encryption private key and create public key from it
        PublicKey publicKey = encryptionKeyPair.getPublic();
        System.out.println(Base64.getUrlEncoder().encodeToString(publicKey.getEncoded()));

        SecretKey generatedSecretKey = KeyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);
        KeyEnvelope keyEnvelope = keyEnvelopeService.create(generatedSecretKey,
                publicKey,
                signingPrivateKey,
                "123",
                "456",
                "789");

        assertNotNull(keyEnvelope.getKeyEnvelopeSignature());
        assertNotNull(keyEnvelope.getKey());

        System.out.println("Envelope");
        System.out.println(new JSONObject(keyEnvelope));
    }

}
