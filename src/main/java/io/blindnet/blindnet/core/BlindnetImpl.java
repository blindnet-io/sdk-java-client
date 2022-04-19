package io.blindnet.blindnet.core;

import io.blindnet.blindnet.Blindnet;
import io.blindnet.blindnet.domain.message.MessageArrayWrapper;
import io.blindnet.blindnet.domain.message.MessageStreamWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.internal.*;

import java.io.InputStream;

/**
 * Provides implementation of Blindnet SDK Api.
 */
class BlindnetImpl implements Blindnet {

    private final TokenConfig tokenConfig = TokenConfig.INSTANCE;
    private final UserService userService;
    private final MessageService messageService;
    private final KeyEncryptionService keyEncryptionService;

    public BlindnetImpl(String keyFolderPath, String token, String serverUrl) {
        this(keyFolderPath, token);
        ApiConfig.INSTANCE.setup(serverUrl);
    }

    public BlindnetImpl(String keyFolderPath, String token) {
        KeyStorage keyStorage = KeyStorage.getInstance();
        if (keyFolderPath != null) {
            KeyStorageConfig.INSTANCE.setup(keyFolderPath);
        } else {
            keyStorage.isAndroid = true;
        }
        tokenConfig.setup(token);
        KeyFactory keyFactory = new KeyFactory();
        EncryptionService encryptionService = new EncryptionService(keyFactory);
        SigningService signingService = new SigningService();
        KeyEnvelopeService keyEnvelopeService = new KeyEnvelopeService();

        ApiClient apiClient = new ApiClient(keyStorage,
                keyFactory,
                encryptionService,
                HttpClient.getInstance(),
                keyEnvelopeService
        );

        userService = new UserServiceImpl(keyStorage,
                keyFactory,
                signingService,
                apiClient);

        keyEncryptionService = new KeyEncryptionServiceImpl(keyStorage,
                keyFactory,
                encryptionService,
                apiClient);

        messageService =  new MessageServiceImpl(keyStorage,
                keyFactory,
                encryptionService,
                signingService,
                keyEnvelopeService,
                apiClient);
    }

    /**
     * Set token that will be used for authorization against blindnet api.
     *
     * @param token a token object.
     */
    @Override
    public void updateToken(String token) {
        tokenConfig.setup(token);
    }

    /**
     * Encrypts private keys and sends them to blindnet api.
     *
     * @param password a password phrase used for encryption of private keys.
     */
    @Override
    public void backupKeys(String password) {
        keyEncryptionService.encrypt(password);
    }

    /**
     * Fetches private keys from blindnet api and stores them locally.
     *
     * @param password a password phrase used for decryption of private keys.
     */
    @Override
    public void retrieveKeys(String password) {
        keyEncryptionService.decrypt(password);
    }

    /**
     * Encrypts message.
     *
     * @param recipientId    a recipient id.
     * @param messageWrapper a message wrapper object.
     * @return encrypted message as byte array.
     */
    @Override
    public byte[] encrypt(String recipientId, MessageArrayWrapper messageWrapper) {
        return messageService.encrypt(recipientId, messageWrapper);
    }

    /**
     * Encrypts message.
     *
     * @param recipientId          a recipient id.
     * @param messageStreamWrapper a message wrapper object.
     * @return encrypted message as input stream.
     */
    @Override
    public InputStream encrypt(String recipientId, MessageStreamWrapper messageStreamWrapper) {
        return messageService.encrypt(recipientId, messageStreamWrapper);
    }

    /**
     * Decrypts message.
     *
     * @param senderId    a sender id.
     * @param recipientId a recipient id.
     * @param data        encrypted message as byte array.
     * @return a message wrapper object.
     */
    @Override
    public MessageArrayWrapper decrypt(String senderId, String recipientId, byte[] data) {
        return messageService.decrypt(senderId, recipientId, data);
    }

    /**
     * Decrypts message.
     *
     * @param senderId    a sender id.
     * @param recipientId a recipient id.
     * @param inputData   encrypted message as input stream.
     * @return a message wrapper object.
     */
    @Override
    public MessageStreamWrapper decrypt(String senderId, String recipientId, InputStream inputData) {
        return messageService.decrypt(senderId, recipientId, inputData);
    }

    /**
     * Registers user on blindnet api.
     *
     * @return a user registration result object.
     */
    @Override
    public UserRegistrationResult register() {
        return userService.register();
    }

    /**
     * Unregisters user from blindnet api.
     */
    @Override
    public void disconnect() {
        userService.unregister();
    }

}
