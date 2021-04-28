package io.blindnet.blindnet.core;

import io.blindnet.blindnet.MessageService;
import io.blindnet.blindnet.domain.KeyEnvelope;
import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import io.blindnet.blindnet.domain.PublicKeyPair;
import io.blindnet.blindnet.exception.BlindnetApiException;

import javax.crypto.SecretKey;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.*;

/**
 * todo javadoc
 *
 * @author stefanveselinovic
 */
public class MessageServiceImpl implements MessageService {

    private static final Logger LOGGER = Logger.getLogger(HttpClient.class.getName());

    private KeyEnvelopeService keyEnvelopeService;
    private JwtService jwtService;
    private BlindnetClient blindnetClient;
    private EncryptionService encryptionService;
    private KeyStorage keyStorage;

    public MessageServiceImpl() {
        // todo to be changed
        keyEnvelopeService = new KeyEnvelopeService();
        jwtService = new JwtService();
        blindnetClient = new BlindnetClient();
        encryptionService = new EncryptionService();
        keyStorage = new KeyStorage();
    }

    /**
     * todo javadoc
     *
     * @param jwt
     * @param recipientId
     * @param messageWrapper
     * @return
     */
    @Override
    public byte[] encrypt(String jwt, String recipientId, MessageArrayWrapper messageWrapper) {
        return encryptionService.encryptMessage(getEncryptionKey(jwt, recipientId), messageWrapper);
    }

    /**
     *
     * @param jwt
     * @param recipientId
     * @param messageStreamWrapper
     * @return
     */
    @Override
    public InputStream encrypt(String jwt, String recipientId, MessageStreamWrapper messageStreamWrapper) {
        return encryptionService.encryptMessage(getEncryptionKey(jwt, recipientId), messageStreamWrapper);
    }

    /**
     * todo javadoc
     *
     * @param jwt
     * @param senderId
     * @param recipientId
     * @param data
     * @return
     */
    @Override
    public MessageArrayWrapper decrypt(String jwt, String senderId, String recipientId, byte[] data) {
        return encryptionService.decryptMessage(blindnetClient.fetchSecretKey(jwt, senderId, recipientId), data);
    }

    /**
     *
     * @param jwt
     * @param senderId
     * @param recipientId
     * @param inputData
     * @return
     */
    @Override
    public MessageStreamWrapper decrypt(String jwt, String senderId, String recipientId, InputStream inputData) {
        return encryptionService.decryptMessage(getEncryptionKey(jwt, recipientId), inputData);
    }

    /**
     *
     * @param jwt
     * @param recipientId
     * @return
     */
    private SecretKey getEncryptionKey(String jwt, String recipientId) {
        String senderId = jwtService.extractUserId(jwt);
        try {
            return blindnetClient.fetchSecretKey(jwt, senderId, recipientId);
        } catch (BlindnetApiException exception) {
            LOGGER.log(Level.INFO, String.format("Unable to fetch secret key from Blindnet API. %s", exception.getMessage()));
        }

        // if secret key is not retrieved from blindnet api
        PublicKeyPair recipientPublicKeyPair = blindnetClient.fetchPublicKeys(jwt, recipientId);
        SecretKey generatedSecretKey = KeyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE);

        PrivateKey senderEncryptionPrivateKey = keyStorage.readEncryptionPrivateKey();
        PublicKey senderEncryptionPublicKey = KeyFactory.extractPublicKey(senderEncryptionPrivateKey,
                RSA_ALGORITHM,
                BC_PROVIDER);
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

        blindnetClient.sendSecretKey(jwt, sendersKeyEnvelope, recipientKeyEnvelope);

        return generatedSecretKey;
    }

}
