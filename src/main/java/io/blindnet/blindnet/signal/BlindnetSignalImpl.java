package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.BlindnetSignal;
import io.blindnet.blindnet.domain.message.MessageArrayWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.internal.*;

import java.io.InputStream;
import java.util.List;

/**
 * Provides implementation of Signal Blindnet SDK Api.
 */
class BlindnetSignalImpl implements BlindnetSignal {

    private final SignalUserService signalUserService;
    private final SignalEncryptionService signalEncryptionService;
    private final SignalBackupService signalBackupService;
    private final SignalIdentityDatabase signalIdentityDatabase;

    public BlindnetSignalImpl(String dbPath, String token, String serverUrl) {
        this(dbPath, token);
        ApiConfig.INSTANCE.setup(serverUrl);
    }

    public BlindnetSignalImpl(String dbPath, String token) {
        TokenConfig.INSTANCE.setup(token);
        DatabaseConfig.INSTANCE.setup(dbPath);

        KeyFactory keyFactory = new KeyFactory();
        SignalKeyFactory signalKeyFactory = new SignalKeyFactory();
        SigningService signingService = new SigningService();
        SignalApiClient signalApiClient = new SignalApiClient(HttpClient.getInstance(), signalKeyFactory);

        SignalSessionDatabase signalSessionDatabase = new SignalSessionDatabase();
        SignalSignedPreKeyDatabase signalSignedPreKeyDatabase = new SignalSignedPreKeyDatabase();
        SignalPreKeyDatabase signalPreKeyDatabase = new SignalPreKeyDatabase();

        SignalSessionStore signalSessionStore = new SignalSessionStore(signalSessionDatabase);

        signalIdentityDatabase = new SignalIdentityDatabase();

        SignalPreKeyStore signalPreKeyStore = new SignalPreKeyStore(signalPreKeyDatabase,
                signalIdentityDatabase,
                signalApiClient,
                signalKeyFactory);
        SignalSignedPreKeyStore signalSignedPreKeyStore = new SignalSignedPreKeyStore(signalSignedPreKeyDatabase);
        SignalIdentityKeyStore signalIdentityKeyStore = new SignalIdentityKeyStore(signalIdentityDatabase);

        EncryptionService encryptionService = new EncryptionService(keyFactory);

        signalUserService = new SignalUserServiceImpl(keyFactory,
                signalKeyFactory,
                signingService,
                signalApiClient,
                signalIdentityKeyStore,
                signalSignedPreKeyStore,
                signalPreKeyStore);

        signalEncryptionService = new SignalEncryptionServiceImpl(signalApiClient,
                signalSessionStore,
                signalPreKeyStore,
                signalSignedPreKeyStore,
                signalIdentityKeyStore);

        signalBackupService = new SignalBackupServiceImpl(keyFactory,
                signalApiClient,
                encryptionService);
    }

    /**
     * Registers user against Signal Blindnet API.
     *
     * @return user registration result object.
     */
    @Override
    public UserRegistrationResult register() {
        return signalUserService.register();
    }

    /**
     * Unregisters/disconnects user against Signal Blindnet API and deletes local user data.
     */
    @Override
    public void disconnect() {
        signalUserService.unregister();
    }

    /**
     * Encrypts message and sends to Signal Blindnet API.
     *
     * @param recipientIds the list of recipient ids.
     * @param messageArrayWrapper a message wrapper.
     */
    @Override
    public void encryptMessage(List<String> recipientIds, MessageArrayWrapper messageArrayWrapper) {
        signalEncryptionService.encryptMessage(recipientIds, messageArrayWrapper);
    }

    /**
     * Fetches messages from Signal Blindnet API and decrypts them.
     *
     * @param deviceId the id of the device.
     * @return a list of messages wrappers.
     */
    @Override
    public List<MessageArrayWrapper> decryptMessage(String deviceId) {
        return signalEncryptionService.decryptMessage(deviceId);
    }

    /* Signal library does not support encryption of stream messages
     *
     * @Override
     * public void encryptMessage(List<String> recipientIds, MessageStreamWrapper messageStreamWrapper) {
     *   signalEncryptionService.encryptMessage(recipientIds, messageStreamWrapper);
     * }
     */

    /* Signal library does not support encryption of stream messages
     *
     * @Override
     * public List<MessageStreamWrapper> decryptMessageAsStream(String deviceId) {
     *   return signalEncryptionService.decryptStreamMessage(deviceId);
     * }
     */

    /**
     * Backups a list of messages using Signal Blindnet API.
     *
     * @param password a backup password.
     * @param newBackup flag indicating whether this is a new fresh backup.
     * @param messages a list of messages.
     */
    @Override
    public void backupMessages(String password, boolean newBackup, List<MessageArrayWrapper> messages) {
        signalBackupService.backup(password, newBackup, messages);
    }

    /**
     * Backups a stream of messages using Signal Blindnet API.
     *
     * @param password a backup password.
     * @param newBackup flag indicating whether this is a new fresh backup.
     * @param messages a stream of messages.
     */
    @Override
    public void backupMessages(String password, boolean newBackup, InputStream messages) {
        signalBackupService.backup(password, newBackup, messages);
    }

    /**
     * Recovers a list of messages from a backup.
     *
     * @param password a backup password.
     * @return a list of messages.
     */
    @Override
    public List<MessageArrayWrapper> recoverMessages(String password) {
        return signalBackupService.recover(password);
    }

    /**
     * Recovers a stream of messages from a backup.
     *
     * @param password a backup password.
     * @return a stream of messages.
     */
    @Override
    public InputStream recoverMessagesAsStream(String password) {
        return signalBackupService.recoverAsStream(password);
    }

    /**
     * Returns an ID of the device.
     *
     * @return an ID of the device.
     */
    @Override
    public int readDeviceId() {
        return signalIdentityDatabase.readLocalDeviceId();
    }

}
