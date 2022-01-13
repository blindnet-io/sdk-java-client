package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.KeyStorageException;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.util.KeyHelper;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Signal pre key store implementation.
 */
class SignalPreKeyStore implements PreKeyStore {

    private static final Object LOCK = new Object();

    private final SignalPreKeyDatabase signalPreKeyDatabase;
    private final SignalIdentityDatabase signalIdentityDatabase;
    private final SignalApiClient signalApiClient;
    private final SignalKeyFactory signalKeyFactory;

    public SignalPreKeyStore(SignalPreKeyDatabase signalPreKeyDatabase,
                             SignalIdentityDatabase signalIdentityDatabase,
                             SignalApiClient signalApiClient,
                             SignalKeyFactory signalKeyFactory) {

        this.signalPreKeyDatabase = signalPreKeyDatabase;
        this.signalIdentityDatabase = signalIdentityDatabase;
        this.signalApiClient = signalApiClient;
        this.signalKeyFactory = signalKeyFactory;
    }

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) {
        synchronized (LOCK) {
            return signalPreKeyDatabase.load(preKeyId).orElseThrow(
                    () -> new KeyStorageException(String.format("Key with % does not exist.", preKeyId)));

        }
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        synchronized (LOCK) {
            signalPreKeyDatabase.store(preKeyId, record);
        }
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        return signalPreKeyDatabase.load(preKeyId).isPresent();
    }

    @Override
    public void removePreKey(int preKeyId) {
        signalPreKeyDatabase.delete(preKeyId);

        // FR-SDK22
        if (signalPreKeyDatabase.countPreKeys() < 6) {
            int startId = ThreadLocalRandom.current().nextInt();
            List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 10);
            preKeys.forEach(preKey -> storePreKey(preKey.getId(), preKey));

            Map<String, String> listOfPublicPreKeys = new HashMap<>();
            preKeys.forEach(key ->
                    listOfPublicPreKeys.put(String.valueOf(key.getId()), Base64.getEncoder().encodeToString(
                            signalKeyFactory.removeKeyTypeByte(key.getKeyPair().getPublicKey().serialize()))));

            signalApiClient.uploadPreKeys(String.valueOf(signalIdentityDatabase.readLocalDeviceId()),
                    listOfPublicPreKeys);
        }
    }

}
