package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.SignatureException;
import io.blindnet.blindnet.internal.KeyFactory;
import io.blindnet.blindnet.internal.SigningService;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static io.blindnet.blindnet.internal.EncryptionConstants.BC_PROVIDER;
import static io.blindnet.blindnet.internal.EncryptionConstants.Ed25519_ALGORITHM;
import static org.junit.jupiter.api.Assertions.*;

public class SigningServiceTest extends AbstractTest {

    private SigningService signingService;
    private KeyPair signingKeyPair;
    private Map<String, String> object;

    @Before
    public void setup() {
        signingService = new SigningService();
        KeyFactory keyFactory = new KeyFactory();
        signingKeyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
        object = new HashMap<>();
        object.put("user_id", "random_id");
    }

    @Test
    @DisplayName("Test signing object flow.")
    public void testSigningObjectFlow() {
        byte[] signature = signingService.sign(new JSONObject(object).toString().getBytes(),
                signingKeyPair.getPrivate(),
                Ed25519_ALGORITHM);

        assertNotNull(signature);
        assertTrue(signingService.verify(new JSONObject(object).toString().getBytes(),
                Base64.getEncoder().encodeToString(signature),
                signingKeyPair.getPublic(),
                Ed25519_ALGORITHM));
    }

    @Test
    @DisplayName("Test signing string flow.")
    public void testSigningStringFlow() {
        String randomData = UUID.randomUUID().toString();
        byte[] signature = signingService.sign(randomData,
                signingKeyPair.getPrivate(),
                Ed25519_ALGORITHM);

        assertNotNull(signature);
        assertTrue(signingService.verify(randomData.getBytes(),
                Base64.getEncoder().encodeToString(signature),
                signingKeyPair.getPublic(),
                Ed25519_ALGORITHM));
    }

    @Test
    @DisplayName("Test signing flow with invalid arguments.")
    public void testSigningFlowWithInvalidArgs() {
        SignatureException signSignatureException = assertThrows(SignatureException.class,
                () -> signingService.sign(new JSONObject(object).toString().getBytes(),
                        signingKeyPair.getPrivate(),
                        INVALID_EdDSA_ALGORITHM));
        assertTrue(signSignatureException.getMessage().contains("Error during signature creation."));

        SignatureException verifySignatureException = assertThrows(SignatureException.class,
                () -> signingService.verify(new JSONObject(object).toString().getBytes(),
                        "random_signature",
                        signingKeyPair.getPublic(),
                        INVALID_EdDSA_ALGORITHM));
        assertTrue(verifySignatureException.getMessage().contains("Error during signature validation."));
    }

}
