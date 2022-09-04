package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.KeyStorageException;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

import java.util.List;

/**
 * Implementation of signed pre key store.
 */
class SignalSignedPreKeyStore implements SignedPreKeyStore {

    private static final Object LOCK = new Object();

    private final SignalSignedPreKeyDatabase signalSignedPreKeyDatabase;

    public SignalSignedPreKeyStore(SignalSignedPreKeyDatabase signalSignedPreKeyDatabase) {
        this.signalSignedPreKeyDatabase = signalSignedPreKeyDatabase;
    }

    /**
     * Returns a signed pre key.
     *
     * @param signedPreKeyId the ID of the local SignedPreKeyRecord.
     * @return a signed pre key record.
     */
    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) {
        synchronized (LOCK) {
            return signalSignedPreKeyDatabase.load(signedPreKeyId).orElseThrow(
                    () -> new KeyStorageException(String.format("Key with % does not exist.", signedPreKeyId)));
        }
    }

    /**
     * Loads a list of signed pre keys.
     *
     * @return a list of signed pre keys.
     */
    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        synchronized (LOCK) {
            return signalSignedPreKeyDatabase.loadRecords();
        }
    }

    /**
     * Stores a signed pre key.
     *
     * @param signedPreKeyId the ID of the SignedPreKeyRecord to store.
     * @param record         the SignedPreKeyRecord.
     */
    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        synchronized (LOCK) {
            signalSignedPreKeyDatabase.store(signedPreKeyId, record);
        }
    }

    /**
     * Checks whether a database contains a signed pre key.
     *
     * @param signedPreKeyId A SignedPreKeyRecord ID.
     * @return an indicator whether a signed pre key is in the database.
     */
    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        return signalSignedPreKeyDatabase.load(signedPreKeyId).isPresent();
    }

    /**
     * Removes a signed pre key from the database.
     *
     * @param signedPreKeyId The ID of the SignedPreKeyRecord to remove.
     */
    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        signalSignedPreKeyDatabase.delete(signedPreKeyId);
    }

}
