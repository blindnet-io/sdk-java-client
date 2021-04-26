package io.blindnet.blindnet.core;

import io.blindnet.blindnet.MessageService;
import io.blindnet.blindnet.domain.KeyEnvelope;
import io.blindnet.blindnet.domain.MessageWrapper;
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

    //TODO: FR-SDK07;
    /**
     * todo javadoc and The SDK also records the protocol version in the output data
     *
     * @param jwt
     * @param recipientId
     * @param messageWrapper
     * @return
     */
    @Override
    public byte[] encrypt(String jwt, String recipientId, MessageWrapper messageWrapper) {

        String senderId = jwtService.extractUserId(jwt);
        try {
            SecretKey secretKey = blindnetClient.fetchSecretKey(jwt, senderId, recipientId);
            return encryptionService.encryptMessage(secretKey, messageWrapper);
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

        return encryptionService.encryptMessage(generatedSecretKey, messageWrapper);
    }

    //TODO: FR-SDK08;
    @Override
    public byte[] encrypt(String jwt, String recipientId, InputStream metadata, InputStream data) {
        return null;
    }

    //TODO: FR-SDK09;
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
    public MessageWrapper decrypt(String jwt, String senderId, String recipientId, byte[] data) {
        SecretKey secretKey = blindnetClient.fetchSecretKey(jwt, senderId, recipientId);
        return encryptionService.decryptMessage(secretKey, data);
    }

    public MessageWrapper decrypt(String jwt, String senderId, String recipientId, InputStream data) {
        return null;
    }

}
