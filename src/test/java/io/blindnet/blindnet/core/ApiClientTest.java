package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.*;
import io.blindnet.blindnet.internal.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import static io.blindnet.blindnet.internal.ApiClientConstants.PRIVATE_KEYS_ENDPOINT_PATH;
import static io.blindnet.blindnet.internal.ApiClientConstants.SYMMETRIC_KEY_ENDPOINT_PATH;
import static io.blindnet.blindnet.internal.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

public class ApiClientTest extends AbstractTest {

    private ApiClient apiClient;
    private KeyFactory keyFactory;
    private EncryptionService encryptionService;
    private KeyEnvelopeService keyEnvelopeService;
    private SigningService signingService;
    private KeyStorage keyStorage;
    private JwtConfig jwtConfig = JwtConfig.INSTANCE;
    private KeyPair encryptionKeyPair;
    private KeyPair signingKeyPair;

    @Mock
    private HttpClient httpClient;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        keyFactory = new KeyFactory();
        keyStorage = KeyStorage.getInstance();
        encryptionService = new EncryptionService(keyFactory);
        keyEnvelopeService = new KeyEnvelopeService();
        signingService = new SigningService();
        jwtConfig.setup(TEST_JWT);

        apiClient = new ApiClient(KeyStorage.getInstance(),
                keyFactory,
                encryptionService,
                httpClient,
                keyEnvelopeService
        );

        encryptionKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        signingKeyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
    }

    @Test
    @DisplayName("Test registration of a user.")
    public void testRegister() throws IOException {
        String msg = "Registration successful.";
        when(httpClient.post(anyString(), eq(TEST_JWT), any(byte[].class)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(msg)
                        .withBody(new byte[1])
                        .build());

        byte[] publicSigningKeyEncodedWithoutPrefix = Arrays.copyOfRange(
                signingKeyPair.getPublic().getEncoded(), 12, signingKeyPair.getPublic().getEncoded().length);

        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
                encryptionKeyPair.getPublic().getEncoded());

        byte[] signedEncryptionPublicKey = signingService.sign(publicKeyInfo.getEncoded(),
                signingKeyPair.getPrivate(),
                Ed25519_ALGORITHM);
        Base64.Encoder encoder = Base64.getEncoder();

        UserRegistrationResult result = apiClient.register(encoder.encodeToString(publicKeyInfo.getEncoded()),
                encoder.encodeToString(signedEncryptionPublicKey),
                encoder.encodeToString(publicSigningKeyEncodedWithoutPrefix),
                Base64.getUrlEncoder().encodeToString(UUID.randomUUID().toString().getBytes()));

        assertNotNull(result);
        assertTrue(result.isSuccessful());
        assertEquals(result.getMessage(), msg);
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

        SecretKey generatedSecretKey = keyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);

        KeyEnvelope keyEnvelope = keyEnvelopeService.create(generatedSecretKey,
                encryptionKeyPair.getPublic(),
                signingKeyPair.getPrivate(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString());

        assertDoesNotThrow(() -> apiClient.sendSecretKey(keyEnvelope, keyEnvelope));
    }


    @Test
    @DisplayName("Test fetching of secret key.")
    public void testFetchSecretKey() {
        String senderId = UUID.randomUUID().toString();
        String recipientId = UUID.randomUUID().toString();
        String url = ApiConfig.INSTANCE.getServerUrl() + SYMMETRIC_KEY_ENDPOINT_PATH + "?senderID=" + senderId + "&recipientID=" + recipientId;

        keyStorage.storeEncryptionKey(encryptionKeyPair.getPrivate());
        keyStorage.storeSigningKey(signingKeyPair.getPrivate());
        SecretKey generatedSecretKey = keyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);

        KeyEnvelope keyEnvelope = keyEnvelopeService.create(generatedSecretKey,
                encryptionKeyPair.getPublic(),
                signingKeyPair.getPrivate(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString());


        when(httpClient.get(eq(url), eq(TEST_JWT)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(new JSONObject(keyEnvelope).toString().getBytes(StandardCharsets.UTF_8))
                        .build());

        SecretKey secretKey = apiClient.fetchSecretKey(senderId, recipientId);

        assertNotNull(secretKey);
        assertEquals(secretKey.getAlgorithm(), generatedSecretKey.getAlgorithm());
        assertEquals(secretKey.getEncoded().length, generatedSecretKey.getEncoded().length);
        assertEquals(secretKey, generatedSecretKey);
    }

    @Test
    @DisplayName("Test sending of private keys.")
    public void testSendPrivateKeys() {
        when(httpClient.put(anyString(), eq(TEST_JWT), any(byte[].class)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(new byte[1])
                        .build());

        assertDoesNotThrow(() -> apiClient.sendPrivateKeys(UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString()));
    }

    @Test
    @DisplayName("Test fetching of private keys.")
    public void testFetchPrivateKeys() {
        String password = UUID.randomUUID().toString();
        byte[] salt = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH);

        SecretKey secretKey = keyFactory.extractAesKeyFromPassword(password.toCharArray(),
                salt,
                PBKDF_SHA256);

        byte[] encryptedEPK = encryptionService.encrypt(secretKey,
                new JSONObject(new RsaJwk(encryptionKeyPair.getPrivate())).toString().getBytes());
        byte[] encryptedSPK = encryptionService.encrypt(secretKey, signingKeyPair.getPrivate().getEncoded());

        Base64.Encoder encoder = Base64.getEncoder();

        when(httpClient.get(eq(ApiConfig.INSTANCE.getServerUrl() + PRIVATE_KEYS_ENDPOINT_PATH), eq(TEST_JWT)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(new JSONObject().put("encryptedPrivateEncryptionKey", encoder.encodeToString(encryptedEPK))
                                .put("encryptedPrivateSigningKey", encoder.encodeToString(encryptedSPK))
                                .put("keyDerivationSalt", encoder.encodeToString(salt)).toString().getBytes())
                        .build());

        PrivateKeys privateKeys = apiClient.fetchPrivateKeys();

        Base64.Decoder decoder = Base64.getDecoder();
        byte[] fetchedSalt = decoder.decode(privateKeys.getKeyDerivationSalt());
        byte[] fetchedEncryptedEPK = decoder.decode(privateKeys.getEncryptionKey());
        byte[] fetchedEncryptedSPK = decoder.decode(privateKeys.getSigningKey());


        assertEquals(new String(fetchedSalt), new String(salt));
        assertEquals(new String(fetchedEncryptedSPK), new String(encryptedSPK));
        assertEquals(new String(fetchedEncryptedEPK), new String(encryptedEPK));

        PrivateKey fetchedEncryptionPrivateKey = keyFactory.convertToRsaPrivateKey(
                new JSONObject(new String(encryptionService.decrypt(secretKey, fetchedEncryptedEPK))));

        assertEquals(fetchedEncryptionPrivateKey, encryptionKeyPair.getPrivate());

    }

    @Test
    @DisplayName("Test fetching of public keys.")
    public void testFetchPublicKeys() throws IOException {
        String senderId = UUID.randomUUID().toString();

        byte[] publicSigningKeyEncodedWithoutPrefix = Arrays.copyOfRange(
                signingKeyPair.getPublic().getEncoded(), 12, signingKeyPair.getPublic().getEncoded().length);

        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
                encryptionKeyPair.getPublic().getEncoded());

        byte[] signedEncryptionPublicKey = signingService.sign(publicKeyInfo.getEncoded(),
                signingKeyPair.getPrivate(),
                Ed25519_ALGORITHM);
        Base64.Encoder encoder = Base64.getEncoder();

        when(httpClient.get(anyString(), eq(TEST_JWT)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(new JSONObject().put("publicEncryptionKey", encoder.encodeToString(publicKeyInfo.getEncoded()))
                                .put("publicSigningKey", encoder.encodeToString(publicSigningKeyEncodedWithoutPrefix))
                                .put("signedPublicEncryptionKey", encoder.encodeToString(signedEncryptionPublicKey)).toString().getBytes())
                        .build());

        PublicKeys publicKeys = apiClient.fetchPublicKeys(senderId);

        assertEquals(publicKeys.getEncryptionKey(), encryptionKeyPair.getPublic());
        assertEquals(publicKeys.getSigningKey(), signingKeyPair.getPublic());
    }

}
