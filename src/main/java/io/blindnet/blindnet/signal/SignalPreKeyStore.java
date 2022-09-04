package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.KeyStorageException;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.util.KeyHelper;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    /**
     * Loads pre key from the database.
     *
     * @param preKeyId the ID of the local PreKeyRecord.
     * @return a pre key record.
     */
    @Override
    public PreKeyRecord loadPreKey(int preKeyId) {
        synchronized (LOCK) {
            return signalPreKeyDatabase.load(preKeyId).orElseThrow(
                    () -> new KeyStorageException(String.format("Key with % does not exist.", preKeyId)));

        }
    }

    /**
     * Stores pre key to the database.
     *
     * @param preKeyId the ID of the PreKeyRecord to store.
     * @param record   the PreKeyRecord.
     */
    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        synchronized (LOCK) {
            signalPreKeyDatabase.store(preKeyId, record);
        }
    }

    /**
     * Checks whether the database contains pre key.
     *
     * @param preKeyId A PreKeyRecord ID.
     * @return an indicator whether the pre key is stored in the database.
     */
    @Override
    public boolean containsPreKey(int preKeyId) {
        return signalPreKeyDatabase.load(preKeyId).isPresent();
    }

    /**
     * Removes a pre key from the database.
     *
     * @param preKeyId The ID of the PreKeyRecord to remove.
     */
    @Override
    public void removePreKey(int preKeyId) {
        signalPreKeyDatabase.delete(preKeyId);

        // FR-SDK22
        if (signalPreKeyDatabase.countPreKeys() < 6) {
            int startId = new SecureRandom().nextInt();
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
