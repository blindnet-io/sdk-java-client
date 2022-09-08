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

    /**
     * Returns the local identity key pair.
     *
     * @return an identity key pair object.
     */
    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        return signalIdentityDatabase.readLocalIdentity();
    }

    /**
     * Returns a local id.
     *
     * @return a local ID.
     */
    @Override
    public int getLocalRegistrationId() {
        return signalIdentityDatabase.readLocalRegistrationId();
    }

    /**
     * Saves identity into database.
     *
     * @param address     The address of the remote client.
     * @param identityKey The remote client's identity key.
     * @return an indicator whether the save operation was successful.
     */
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

    /**
     * Verifies whether the identity is trusted.
     *
     * @param address     The address of the remote client.
     * @param identityKey The identity key to verify.
     * @param direction   The direction (sending or receiving) this identity is being used for.
     * @return an indicator whether the identity is trusted.
     */
    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        synchronized (LOCK) {
            if (direction == RECEIVING) {
                return true;
            }
            else {
                return getIdentity(address).equals(identityKey);
            }
        }
    }

    /**
     * Returns the identity.
     *
     * @param address The address of the remote client
     * @return an identity key object.
     */
    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        return signalIdentityDatabase.readIdentity(address).orElse(null);
    }

    /**
     * Saves local identity to the database.
     *
     * @param registrationId  a registration ID.
     * @param deviceId        a device ID.
     * @param identityKeyPair an identity key pair.
     */
    public void saveLocalIdentity(int registrationId, int deviceId, IdentityKeyPair identityKeyPair) {
        signalIdentityDatabase.saveLocalIdentity(registrationId, deviceId, identityKeyPair);
    }

    /**
     * Returns an id of the local device.
     *
     * @return an id of the local device.
     */
    public int getLocalDeviceId() {
        return signalIdentityDatabase.readLocalDeviceId();
    }

}
