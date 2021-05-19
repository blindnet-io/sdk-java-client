package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.SignatureException;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static io.blindnet.blindnet.core.EncryptionConstants.BC_PROVIDER;
import static io.blindnet.blindnet.core.EncryptionConstants.Ed25519_ALGORITHM;
import static org.junit.jupiter.api.Assertions.*;

public class SigningServiceTest extends AbstractTest {

    private SigningService signingService;
    private KeyFactory keyFactory;
    private KeyPair signingKeyPair;
    private Map<String, String> object;

    @Before
    public void setup() {
        signingService = new SigningService();
        keyFactory = new KeyFactory();
        signingKeyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
        object = new HashMap<>();
        object.put("user_id", "random_id");
    }

    @Test
    @DisplayName("Test signing flow.")
    public void testSigningFlow() {
        byte[] signature = signingService.sign(object,
                signingKeyPair.getPrivate(),
                Ed25519_ALGORITHM);

        assertNotNull(signature);

        boolean verified = signingService.verify(object,
                Base64.getEncoder().encodeToString(signature),
                signingKeyPair.getPublic(),
                Ed25519_ALGORITHM);

        assertTrue(verified);
    }

    @Test
    @DisplayName("Test signing flow with invalid arguments.")
    public void testSigningFlowWithInvalidArgs() {
        SignatureException signSignatureException = assertThrows(SignatureException.class,
                () -> signingService.sign(object,
                        signingKeyPair.getPrivate(),
                        INVALID_EdDSA_ALGORITHM));
        assertTrue(signSignatureException.getMessage().contains("Error during signature creation."));

        SignatureException verifySignatureException = assertThrows(SignatureException.class,
                () -> signingService.verify(object,
                        "random_signature",
                        signingKeyPair.getPublic(),
                        INVALID_EdDSA_ALGORITHM));
        assertTrue(verifySignatureException.getMessage().contains("Error during signature validation."));
    }

}
