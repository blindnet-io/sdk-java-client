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

    @Override
    public UserRegistrationResult register() {
        return signalUserService.register();
    }

    @Override
    public void disconnect() {
        signalUserService.unregister();
    }

    @Override
    public void encryptMessage(List<String> recipientIds, MessageArrayWrapper messageArrayWrapper) {
        signalEncryptionService.encryptMessage(recipientIds, messageArrayWrapper);
    }

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

    @Override
    public void backupMessages(String password, boolean newBackup, List<MessageArrayWrapper> messages) {
        signalBackupService.backup(password, newBackup, messages);
    }

    @Override
    public void backupMessages(String password, boolean newBackup, InputStream messages) {
        signalBackupService.backup(password, newBackup, messages);
    }

    @Override
    public List<MessageArrayWrapper> recoverMessages(String password) {
        return signalBackupService.recover(password);
    }

    @Override
    public InputStream recoverMessagesAsStream(String password) {
        return signalBackupService.recoverAsStream(password);
    }

    @Override
    public int readDeviceId() {
        return signalIdentityDatabase.readLocalDeviceId();
    }

}
