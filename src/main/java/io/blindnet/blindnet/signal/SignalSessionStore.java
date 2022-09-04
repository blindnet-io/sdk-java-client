package io.blindnet.blindnet.signal;

import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;

import java.util.List;
import java.util.Optional;

/**
 * Implementation of session store.
 */
class SignalSessionStore implements SessionStore {

    private static final Object LOCK = new Object();

    private final SignalSessionDatabase signalSessionDatabase;

    public SignalSessionStore(SignalSessionDatabase signalSessionDatabase) {
        this.signalSessionDatabase = signalSessionDatabase;
    }

    /**
     * Loads session from the database.
     *
     * @param address The name and device ID of the remote client.
     * @return a session record.
     */
    @Override
    public SessionRecord loadSession(SignalProtocolAddress address) {
        synchronized (LOCK) {
            return signalSessionDatabase.load(address).orElse(new SessionRecord());
        }
    }

    /**
     * Returns a list of all devices of the active device.
     *
     * @param name the name of the client.
     * @return a list of device ids.
     */
    @Override
    public List<Integer> getSubDeviceSessions(String name) {
        synchronized (LOCK) {
            return signalSessionDatabase.getSubDeviceSessions(name);
        }
    }

    /**
     * Stores a session to the database.
     *
     * @param address the address of the remote client.
     * @param record  the current SessionRecord for the remote client.
     */
    @Override
    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        synchronized (LOCK) {
            if (containsSession(address)) {
                signalSessionDatabase.updateSession(address, record);
            } else {
                signalSessionDatabase.store(address, record);
            }
        }
    }

    /**
     * Checks whether the database contains a session for the recipient's address.
     *
     * @param address the address of the remote client.
     * @return an indicator whether the session is present in the database.
     */
    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        synchronized (LOCK) {
            return signalSessionDatabase.load(address).isPresent();
        }
    }

    /**
     * Deletes a session from the database.
     *
     * @param address the address of the remote client.
     */
    @Override
    public void deleteSession(SignalProtocolAddress address) {
        synchronized (LOCK) {
            signalSessionDatabase.delete(address);
        }
    }

    /**
     * Deletes all sessions from the database.
     *
     * @param name the name of the remote client.
     */
    @Override
    public void deleteAllSessions(String name) {
        synchronized (LOCK) {
            signalSessionDatabase.deleteAll(name);
        }
    }

}
