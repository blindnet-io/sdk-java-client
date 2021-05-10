package io.blindnet.blindnet.core;

import io.blindnet.blindnet.MessageService;
import io.blindnet.blindnet.domain.KeyEnvelope;
import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import io.blindnet.blindnet.domain.PublicKeyPair;
import io.blindnet.blindnet.exception.BlindnetApiException;
import io.blindnet.blindnet.exception.SignatureException;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;
import static java.util.Objects.requireNonNull;

/**
 * Provides API for encryption and decryption of messages.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class MessageServiceImpl implements MessageService {

    private static final Logger LOGGER = Logger.getLogger(HttpClient.class.getName());

    private final KeyStorage keyStorage;
    private final KeyFactory keyFactory;
    private final EncryptionService encryptionService;
    private final SigningService signingService;
    private final KeyEnvelopeService keyEnvelopeService;
    private final BlindnetClient blindnetClient;
    private final JwtConfig jwtConfig;

    public MessageServiceImpl(KeyStorage keyStorage,
                              KeyFactory keyFactory,
                              EncryptionService encryptionService,
                              SigningService signingService,
                              KeyEnvelopeService keyEnvelopeService,
                              BlindnetClient blindnetClient) {

        this.keyStorage = keyStorage;
        this.keyFactory = keyFactory;
        this.encryptionService = encryptionService;
        this.signingService = signingService;
        this.keyEnvelopeService = keyEnvelopeService;
        this.blindnetClient = blindnetClient;
        this.jwtConfig = JwtConfig.INSTANCE;
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
        return encryptionService.decryptMessage(blindnetClient.fetchSecretKey(senderId, recipientId), data);
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
        return encryptionService.decryptMessage(getEncryptionKey(recipientId), inputData);
    }

    /**
     * Returns secret key by retrieving it from  Blindnet API or generating new one.
     *
     * @param recipientId an id of the recipient.
     * @return a secret key object.
     */
    private SecretKey getEncryptionKey(String recipientId) {
        String senderId = JwtUtil.extractUserId(requireNonNull(jwtConfig.getJwt(), "JWT not configured properly."));
        try {
            return blindnetClient.fetchSecretKey(senderId, recipientId);
        } catch (BlindnetApiException exception) {
            LOGGER.log(Level.INFO, String.format("Unable to fetch secret key from Blindnet API. %s", exception.getMessage()));
        }

        // if secret key is not retrieved from blindnet api
        PublicKeyPair recipientPublicKeyPair = blindnetClient.fetchPublicKeys(recipientId);

        if (!signingService.verify(recipientPublicKeyPair.getEncryptionKey(),
                recipientPublicKeyPair.getSignedPublicEncryptionKey(),
                recipientPublicKeyPair.getSigningKey(),
                Ed25519_ALGORITHM)) {

            String msg = "Unable to verify public encryption key signature.";
            LOGGER.log(Level.SEVERE, msg);
            throw new SignatureException(msg);
        }
        keyStorage.storeRecipientSigningPublicKey(recipientPublicKeyPair.getSigningKey(), recipientId);

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
                recipientPublicKeyPair.getEncryptionKey(),
                senderSigningPrivateKey,
                recipientId,
                recipientId,
                senderId
        );

        blindnetClient.sendSecretKey(sendersKeyEnvelope, recipientKeyEnvelope);

        return generatedSecretKey;
    }

}
