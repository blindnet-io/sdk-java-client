package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.HttpResponse;
import io.blindnet.blindnet.domain.RsaJwk;
import io.blindnet.blindnet.internal.EncryptionService;
import io.blindnet.blindnet.internal.HttpClient;
import io.blindnet.blindnet.internal.KeyFactory;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.KeyPair;
import java.util.Base64;
import java.util.UUID;

import static io.blindnet.blindnet.internal.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class KeyEncryptionServiceTest extends AbstractTest {

    private KeyEncryptionService keyEncryptionService;
    private KeyFactory keyFactory;
    private KeyStorage keyStorage;
    private KeyPair encryptionKeyPair;
    private KeyPair signingKeyPair;
    private EncryptionService encryptionService;

    @Mock
    private HttpClient httpClient;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        keyFactory = new KeyFactory();
        encryptionService = new EncryptionService(keyFactory);
        EncryptionService encryptionService = new EncryptionService(keyFactory);
        keyStorage = KeyStorage.getInstance();
        KeyEnvelopeService keyEnvelopeService = new KeyEnvelopeService();
        ApiClient apiClient = new ApiClient(keyStorage,
                keyFactory,
                encryptionService,
                httpClient,
                keyEnvelopeService
        );
        keyEncryptionService = new KeyEncryptionServiceImpl(keyStorage,
                keyFactory,
                encryptionService,
                apiClient);

        encryptionKeyPair = keyFactory.generateRSAKeyPair();
        signingKeyPair = keyFactory.generateEd25519KeyPair();
    }

    @Test
    @DisplayName("Test encryption.")
    public void testEncrypt() {
        String password = UUID.randomUUID().toString();
        keyStorage.storeEncryptionKey(encryptionKeyPair.getPrivate());
        keyStorage.storeSigningKey(signingKeyPair.getPrivate());

        when(httpClient.put(anyString(), any(byte[].class)))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(new byte[1])
                        .build());
        assertDoesNotThrow(() -> keyEncryptionService.encrypt(password));
    }

    @Test
    @DisplayName("Test decryption.")
    public void testDecryption() throws IOException {
        String password = UUID.randomUUID().toString();
        byte[] salt = keyFactory.generateRandom(NONCE_IV_ALGORITHM, BC_PROVIDER, SALT_LENGTH);
        SecretKey secretKey = keyFactory.extractAesKeyFromPassword(password.toCharArray(),
                salt,
                PBKDF_SHA256);
        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                new DEROctetString(signingKeyPair.getPrivate().getEncoded()));

        byte[] encryptedEPK = encryptionService.encrypt(secretKey,
                new JSONObject(new RsaJwk(encryptionKeyPair.getPrivate())).toString().getBytes());
        byte[] encryptedSPK = encryptionService.encrypt(secretKey, privateKeyInfo.getEncoded());


        Base64.Encoder encoder = Base64.getEncoder();
        JSONObject jsonObject = new JSONObject().put("encryptedPrivateEncryptionKey", encoder.encodeToString(encryptedEPK))
                .put("encryptedPrivateSigningKey", encoder.encodeToString(encryptedSPK))
                .put("keyDerivationSalt", encoder.encodeToString(salt));
        when(httpClient.get(anyString()))
                .thenReturn(new HttpResponse.Builder(HttpURLConnection.HTTP_OK)
                        .withMessage(UUID.randomUUID().toString())
                        .withBody(jsonObject.toString().getBytes())
                        .build());

        assertDoesNotThrow(() -> keyEncryptionService.decrypt(password));
    }

}
