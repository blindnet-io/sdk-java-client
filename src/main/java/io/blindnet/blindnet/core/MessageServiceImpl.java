package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.key.KeyEnvelope;
import io.blindnet.blindnet.domain.message.MessageArrayWrapper;
import io.blindnet.blindnet.domain.message.MessageStreamWrapper;
import io.blindnet.blindnet.domain.key.PublicKeys;
import io.blindnet.blindnet.exception.BlindnetApiException;
import io.blindnet.blindnet.exception.KeyConstructionException;
import io.blindnet.blindnet.exception.SignatureException;
import io.blindnet.blindnet.internal.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import static io.blindnet.blindnet.internal.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * Default implementation of message service.
 */
public class MessageServiceImpl implements MessageService {

    private final KeyStorage keyStorage;
    private final KeyFactory keyFactory;
    private final EncryptionService encryptionService;
    private final SigningService signingService;
    private final KeyEnvelopeService keyEnvelopeService;
    private final ApiClient apiClient;
    private final TokenConfig tokenConfig;

    public MessageServiceImpl(KeyStorage keyStorage,
                              KeyFactory keyFactory,
                              EncryptionService encryptionService,
                              SigningService signingService,
                              KeyEnvelopeService keyEnvelopeService,
                              ApiClient apiClient) {

        this.keyStorage = keyStorage;
        this.keyFactory = keyFactory;
        this.encryptionService = encryptionService;
        this.signingService = signingService;
        this.keyEnvelopeService = keyEnvelopeService;
        this.apiClient = apiClient;
        this.tokenConfig = TokenConfig.INSTANCE;
    }

    /**
     * Encrypts message and message metadata.
     *
     * @param recipientId an id of the recipient.
     * @param messageWrapper a message wrapper object.
     * @return encrypted message and message metadata as an byte array.
     */
    @Override
    public byte[] encrypt(String recipientId, MessageArrayWrapper messageWrapper) {
        return encryptionService.encryptMessage(getEncryptionKey(recipientId), messageWrapper);
    }

    /**
     * Encrypts message and message metadata.
     *
     * @param recipientId an id of the recipient.
     * @param messageStreamWrapper a message wrapper object.
     * @return encrypted message and message metadata as an input stream.
     */
    @Override
    public InputStream encrypt(String recipientId, MessageStreamWrapper messageStreamWrapper) {
        return encryptionService.encryptMessage(getEncryptionKey(recipientId), messageStreamWrapper);
    }

    /**
     * Decrypts message and message metadata.
     *
     * @param senderId an id of the sender.
     * @param recipientId an id of the recipient.
     * @param data encrypted message and message metadata as byte array.
     * @return decrypted message and message metadata as message wrapper object.
     */
    @Override
    public MessageArrayWrapper decrypt(String senderId, String recipientId, byte[] data) {
        return encryptionService.decryptMessage(apiClient.fetchSecretKey(senderId, recipientId), data);
    }

    /**
     * Decrypts message and message metadata.
     *
     * @param senderId an id of the sender.
     * @param recipientId an id of the recipient.
     * @param inputData encrypted message and message metadata as input stream.
     * @return decrypted message and message metadata as message wrapper object.
     */
    @Override
    public MessageStreamWrapper decrypt(String senderId, String recipientId, InputStream inputData) {
        return encryptionService.decryptMessage(apiClient.fetchSecretKey(senderId, recipientId), inputData);
    }

    /**
     * Returns secret key by retrieving it from  Blindnet API or generating new one.
     *
     * @param recipientId an id of the recipient.
     * @return a secret key object.
     */
    private SecretKey getEncryptionKey(String recipientId) {
        String senderId = TokenUtil.extractUserId(requireNonNull(tokenConfig.getToken(), "Token not configured properly."));
        try {
            return apiClient.fetchSecretKey(senderId, recipientId);
        } catch (BlindnetApiException exception) {
            // if no fetch key is found generate and upload new one
        }

        // if secret key is not retrieved from blindnet api
        PublicKeys recipientPublicKeys = apiClient.fetchPublicKeys(recipientId);

        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
                recipientPublicKeys.getEncryptionKey().getEncoded());
        try {
            if (!signingService.verify(publicKeyInfo.getEncoded(),
                    recipientPublicKeys.getSignedPublicEncryptionKey(),
                    recipientPublicKeys.getSigningKey(),
                    Ed25519_ALGORITHM)) {

                throw new SignatureException("Unable to verify public encryption key signature.");
            }
        } catch (IOException exception) {
            throw new KeyConstructionException("Error while converting public key to SPKI format.");
        }
        keyStorage.storeRecipientSigningPublicKey(recipientPublicKeys.getSigningKey(), recipientId);

        SecretKey generatedSecretKey = keyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);

        PrivateKey senderEncryptionPrivateKey = keyStorage.readEncryptionPrivateKey();
        PublicKey senderEncryptionPublicKey = keyFactory.extractRsaPublicKey(senderEncryptionPrivateKey);
        PrivateKey senderSigningPrivateKey = keyStorage.readSigningPrivateKey();

        KeyEnvelope sendersKeyEnvelope = keyEnvelopeService.create(generatedSecretKey,
                senderEncryptionPublicKey,
                senderSigningPrivateKey,
                senderId,
                recipientId,
                senderId);

        KeyEnvelope recipientKeyEnvelope = keyEnvelopeService.create(generatedSecretKey,
                recipientPublicKeys.getEncryptionKey(),
                senderSigningPrivateKey,
                recipientId,
                recipientId,
                senderId
        );

        apiClient.sendSecretKey(sendersKeyEnvelope, recipientKeyEnvelope);

        return generatedSecretKey;
    }

}
