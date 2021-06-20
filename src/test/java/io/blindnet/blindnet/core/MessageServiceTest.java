package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import io.blindnet.blindnet.domain.PublicKeys;
import io.blindnet.blindnet.exception.BlindnetApiException;
import io.blindnet.blindnet.exception.SignatureException;
import io.blindnet.blindnet.internal.KeyFactory;
import io.blindnet.blindnet.internal.KeyStorage;
import io.blindnet.blindnet.internal.SigningService;
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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static io.blindnet.blindnet.internal.EncryptionConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

public class MessageServiceTest extends AbstractTest {

    private EncryptionService encryptionService;
    private MessageService messageService;

    private SecretKey secretKey;
    private KeyPair encryptionKeyPair;
    private KeyPair signingKeyPair;
    private PublicKeys publicKeys;
    private final Map<String, Object> metadata = new HashMap<>();
    private final String data = "random-data";
    private String senderId;
    private String recipientId;

    @Mock
    private ApiClient apiClient;

    @Before
    public void setUp() throws IOException {
        MockitoAnnotations.openMocks(this);

        metadata.put("metadatakey", "metadatadata");
        KeyFactory keyFactory = new KeyFactory();
        encryptionService = new EncryptionService(keyFactory);
        SigningService signingService = new SigningService();
        KeyEnvelopeService keyEnvelopeService = new KeyEnvelopeService();
        KeyStorage keyStorage = KeyStorage.getInstance();

        messageService = new MessageServiceImpl(keyStorage,
                keyFactory,
                encryptionService,
                signingService,
                keyEnvelopeService,
                apiClient);

        senderId = UUID.randomUUID().toString();
        recipientId = UUID.randomUUID().toString();

        secretKey = keyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);
        encryptionKeyPair = keyFactory.generateKeyPair(RSA_ALGORITHM, BC_PROVIDER, RSA_KEY_SIZE_4096);
        keyStorage.storeEncryptionKey(encryptionKeyPair.getPrivate());
        signingKeyPair = keyFactory.generateKeyPair(Ed25519_ALGORITHM, BC_PROVIDER, -1);
        keyStorage.storeSigningKey(signingKeyPair.getPrivate());

        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
                encryptionKeyPair.getPublic().getEncoded());

        byte[] signedEncryptionPublicKey = signingService.sign(publicKeyInfo.getEncoded(),
                signingKeyPair.getPrivate(),
                Ed25519_ALGORITHM);
        publicKeys = new PublicKeys(encryptionKeyPair.getPublic(),
                signingKeyPair.getPublic(),
                Base64.getEncoder().encodeToString(signedEncryptionPublicKey));
    }

    @Test
    @DisplayName("Test encryption using byte arrays.")
    public void testEncryptionUsingByteArrays() {
        when(apiClient.fetchSecretKey(anyString(), anyString()))
                .thenThrow(new BlindnetApiException("Secret key not found."));

        when(apiClient.fetchPublicKeys(anyString()))
                .thenReturn(publicKeys);
        doNothing().when(apiClient).sendSecretKey(any(), any());

        assertDoesNotThrow(() -> messageService.encrypt(UUID.randomUUID().toString(),
                new MessageArrayWrapper(metadata, data.getBytes())));
    }

    @Test
    @DisplayName("Test encryption using byte arrays.")
    public void testEncryptionUsingByteArrays_thenInvalidSignature() {
        when(apiClient.fetchSecretKey(anyString(), anyString()))
                .thenThrow(new BlindnetApiException("Secret key not found."));

        publicKeys = new PublicKeys(encryptionKeyPair.getPublic(),
                signingKeyPair.getPublic(),
                Base64.getEncoder().encodeToString(UUID.randomUUID().toString().getBytes()));

        when(apiClient.fetchPublicKeys(anyString()))
                .thenReturn(publicKeys);
        doNothing().when(apiClient).sendSecretKey(any(), any());

        SignatureException signatureException = assertThrows(SignatureException.class,
                () -> messageService.encrypt(UUID.randomUUID().toString(),
                        new MessageArrayWrapper(metadata, data.getBytes())));
        assertTrue(signatureException.getMessage().contains("Unable to verify public encryption key signature."));
    }


    @Test
    @DisplayName("Test encryption using input stream.s")
    public void testEncryptionUsingInputStreams() {
        when(apiClient.fetchSecretKey(anyString(), anyString()))
                .thenThrow(new BlindnetApiException("Secret key not found."));
        when(apiClient.fetchPublicKeys(anyString()))
                .thenReturn(publicKeys);
        doNothing().when(apiClient).sendSecretKey(any(), any());

        assertDoesNotThrow(() -> messageService.encrypt(UUID.randomUUID().toString(),
                new MessageStreamWrapper(metadata, new ByteArrayInputStream(data.getBytes()))));
    }

    @Test
    @DisplayName("Test decryption using byte arrays.")
    public void testDecryptionUsingByteArrays() {
        when(apiClient.fetchSecretKey(senderId, recipientId))
                .thenReturn(secretKey);

        byte[] metadataBA = new JSONObject(metadata).toString().getBytes();
        byte[] metadataLengthBA = ByteBuffer.allocate(4).putInt(metadataBA.length).array();
        byte[] dataToEncrypt = ByteBuffer.allocate(metadataLengthBA.length +
                metadataBA.length +
                data.getBytes().length)
                .put(metadataLengthBA)
                .put(metadataBA)
                .put(data.getBytes())
                .array();

        byte[] encryptedData = encryptionService.encrypt(secretKey, dataToEncrypt);

        MessageArrayWrapper messageArrayWrapper = messageService.decrypt(senderId, recipientId, encryptedData);
        assertNotNull(messageArrayWrapper);
        assertNotNull(messageArrayWrapper.getMetadata());
        assertNotNull(messageArrayWrapper.getData());
        assertArrayEquals(messageArrayWrapper.getMetadata().values().toArray(), metadata.values().toArray());
        assertEquals(new String(messageArrayWrapper.getData()), data);
    }

    @Test
    @DisplayName("Test decryption using input streams.")
    public void testDecryptionUsingInputStreams() throws IOException {
        when(apiClient.fetchSecretKey(senderId, recipientId))
                .thenReturn(secretKey);

        InputStream encryptedInputStream = encryptionService.encryptMessage(secretKey,
                new MessageStreamWrapper(metadata, new ByteArrayInputStream(data.getBytes())));

        MessageStreamWrapper messageStreamWrapper = messageService.decrypt(senderId, recipientId, encryptedInputStream);

        assertNotNull(messageStreamWrapper);
        assertNotNull(messageStreamWrapper.getMetadata());
        assertNotNull(messageStreamWrapper.getData());
        assertArrayEquals(messageStreamWrapper.getMetadata().values().toArray(), metadata.values().toArray());

        byte[] decryptedData = new byte[11];
        messageStreamWrapper.getData().read(decryptedData);
        assertEquals(new String(decryptedData), data);
    }

}
