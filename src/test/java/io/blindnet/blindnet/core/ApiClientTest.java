package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.HttpResponse;
import io.blindnet.blindnet.domain.KeyEnvelope;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.KeyPair;
import java.util.UUID;

import static io.blindnet.blindnet.core.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

public class ApiClientTest extends AbstractTest {

    private ApiClient apiClient;
    private KeyFactory keyFactory;
    private EncryptionService encryptionService;
    private KeyEnvelopeService keyEnvelopeService;

    @Mock
    private HttpClient httpClient;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        keyFactory = new KeyFactory();
        encryptionService = new EncryptionService(keyFactory);
        keyEnvelopeService = new KeyEnvelopeService();
        JwtConfig.INSTANCE.setup(TEST_JWT);

        apiClient = new ApiClient(KeyStorage.getInstance(),
                keyFactory,
                encryptionService,
                httpClient,
                keyEnvelopeService
        );
    }

    @Test
    @DisplayName("Test registration of a user.")
    public void testRegister_thenSuccess() throws IOException {
        String msg = "Registration successful.";
        when(httpClient.post(anyString(), eq(TEST_JWT), any(byte[].class)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(msg)
                        .withBody(new byte[1])
                        .build());

        KeyPair encryptionKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        KeyPair signingKeyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);

//        UserRegistrationResult result = blindnetClient.register(
//                encryptionKeyPair.getPublic(),
//                "".getBytes(),
//                signingKeyPair.getPublic(),
//                UUID.randomUUID().toString().getBytes());
//
//        assertNotNull(result);
//        assertTrue(result.isSuccessful());
//        assertEquals(result.getMessage(), msg);
    }

    @Test
    @DisplayName("Test registration of a user.")
    public void testRegister_thenNotNull() {
        when(httpClient.post(anyString(), eq(TEST_JWT), any(byte[].class)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_NOT_FOUND)
                        .withMessage("User not found.")
                        .withBody(null)
                        .build());

        KeyPair encryptionKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        KeyPair signingKeyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);

//        BlindnetApiException notFoundException = assertThrows(BlindnetApiException.class,
//                () -> blindnetClient.register(
//                        encryptionKeyPair.getPublic(),
//                        "".getBytes(),
//                        signingKeyPair.getPublic(),
//                        UUID.randomUUID().toString().getBytes()));
//
//        assertTrue(notFoundException.getMessage().contains("Algorithm name cannot be null."));
    }

    @Test
    @DisplayName("Test unregistering of a user.")
    public void testUnregister() {
        when(httpClient.delete(anyString(), eq(TEST_JWT)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(new byte[1])
                        .build());

        assertDoesNotThrow(() -> apiClient.unregister());
    }

    @Test
    @DisplayName("Test sending of secret key.")
    public void testSendSecretKey() {
        when(httpClient.post(anyString(), eq(TEST_JWT), any(byte[].class)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(new byte[1])
                        .build());

        KeyPair encryptionKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        KeyPair signingKeyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
        SecretKey generatedSecretKey = keyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);

        KeyEnvelope keyEnvelope = keyEnvelopeService.create(generatedSecretKey,
                encryptionKeyPair.getPublic(),
                signingKeyPair.getPrivate(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString());

        assertDoesNotThrow(() -> apiClient.sendSecretKey(keyEnvelope, keyEnvelope));
    }

}
