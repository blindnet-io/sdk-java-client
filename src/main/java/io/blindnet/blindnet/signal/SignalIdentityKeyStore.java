package io.blindnet.blindnet.signal;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.IdentityKeyStore;

import java.util.Optional;

import static org.whispersystems.libsignal.state.IdentityKeyStore.Direction.RECEIVING;

/**
 * Signal Identity key store implementation.
 */
class SignalIdentityKeyStore implements IdentityKeyStore {

    private static final Object LOCK = new Object();

    private final SignalIdentityDatabase signalIdentityDatabase;

    public SignalIdentityKeyStore(SignalIdentityDatabase signalIdentityDatabase) {
        this.signalIdentityDatabase = signalIdentityDatabase;
    }

    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        return signalIdentityDatabase.readLocalIdentity();
    }

    @Override
    public int getLocalRegistrationId() {
        return signalIdentityDatabase.readLocalRegistrationId();
    }

    @Override
    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        synchronized (LOCK) {
            Optional<IdentityKey> optionalIdentityKey = signalIdentityDatabase.readIdentity(address);

            if (optionalIdentityKey.isPresent()) {
                // replace identity key if exists
                signalIdentityDatabase.deleteIdentity(address);
            }

            signalIdentityDatabase.saveIdentity(address, identityKey);
            return true;
        }
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        synchronized (LOCK) {
            if (direction == RECEIVING) {
                return true;
            }
            // todo check this
//            else {
//
//            }
            return true;
        }
    }

    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        return signalIdentityDatabase.readIdentity(address).orElse(null);
    }

    public void saveLocalIdentity(int registrationId, int deviceId, IdentityKeyPair identityKeyPair) {
        signalIdentityDatabase.saveLocalIdentity(registrationId, deviceId, identityKeyPair);
    }

    public int getLocalDeviceId() {
        return signalIdentityDatabase.readLocalDeviceId();
    }

}
