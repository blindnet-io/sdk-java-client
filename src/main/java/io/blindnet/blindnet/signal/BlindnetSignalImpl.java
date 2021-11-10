package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.BlindnetSignal;
import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.internal.*;
import org.whispersystems.libsignal.InvalidKeyException;

import java.io.InputStream;
import java.util.List;

public class BlindnetSignalImpl implements BlindnetSignal {

    private final SignalUserService signalUserService;
    private final SignalEncryptionService signalEncryptionService;
    private final SignalBackupService signalBackupService;
    private final SignalIdentityDatabase signalIdentityDatabase;

    public BlindnetSignalImpl(String dbPath, String jwt, String serverUrl) {
        this(dbPath, jwt);
        ApiConfig.INSTANCE.setup(serverUrl);
    }

    public BlindnetSignalImpl(String dbPath, String jwt) {
        JwtConfig.INSTANCE.setup(jwt);
        DatabaseConfig.INSTANCE.setup(dbPath);

        // todo fix dependencies
        KeyFactory keyFactory = new KeyFactory();
        SignalKeyFactory signalKeyFactory = new SignalKeyFactory();
        SigningService signingService = new SigningService();
        SignalApiClient signalApiClient = new SignalApiClient(HttpClient.getInstance(), signalKeyFactory);

        DatabaseService databaseService = new DatabaseService();

        SignalSessionDatabase signalSessionDatabase = new SignalSessionDatabase(databaseService);
        signalIdentityDatabase = new SignalIdentityDatabase(databaseService);
        SignalSignedPreKeyDatabase signalSignedPreKeyDatabase = new SignalSignedPreKeyDatabase(databaseService);
        SignalPreKeyDatabase signalPreKeyDatabase = new SignalPreKeyDatabase(databaseService);

        SignalSessionStore signalSessionStore = new SignalSessionStore(signalSessionDatabase);
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
    public UserRegistrationResult register() throws InvalidKeyException {
        return signalUserService.register();
    }

    @Override
    public void unregister() {
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

    @Override
    public void encryptMessage(List<String> recipientIds, MessageStreamWrapper messageStreamWrapper) {
        signalEncryptionService.encryptMessage(recipientIds, messageStreamWrapper);
    }

    @Override
    public List<MessageStreamWrapper> decryptStreamMessage(String deviceId) {
        return signalEncryptionService.decryptStreamMessage(deviceId);
    }

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
