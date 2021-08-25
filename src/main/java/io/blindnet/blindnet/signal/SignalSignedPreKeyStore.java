package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.KeyStorageException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class SignalSignedPreKeyStore implements SignedPreKeyStore {

    private static final Object LOCK = new Object();

    private final SignalSignedPreKeyDatabase signalSignedPreKeyDatabase;

    public SignalSignedPreKeyStore(SignalSignedPreKeyDatabase signalSignedPreKeyDatabase) {
        this.signalSignedPreKeyDatabase = signalSignedPreKeyDatabase;
    }

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) {
        synchronized (LOCK) {
            return signalSignedPreKeyDatabase.load(signedPreKeyId).orElseThrow(
                    () -> new KeyStorageException(String.format("Key with % does not exist.", signedPreKeyId)));
        }
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        synchronized (LOCK) {
            return signalSignedPreKeyDatabase.loadRecords();
        }
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        synchronized (LOCK) {
            signalSignedPreKeyDatabase.store(signedPreKeyId, record);
        }
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        return signalSignedPreKeyDatabase.load(signedPreKeyId).isPresent();
    }

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        signalSignedPreKeyDatabase.delete(signedPreKeyId);
    }

}
