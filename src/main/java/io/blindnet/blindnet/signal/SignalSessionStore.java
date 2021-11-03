package io.blindnet.blindnet.signal;

import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;

import java.util.List;
import java.util.Optional;

public class SignalSessionStore implements SessionStore {

    private static final Object LOCK = new Object();

    private final SignalSessionDatabase signalSessionDatabase;

    public SignalSessionStore(SignalSessionDatabase signalSessionDatabase) {
        this.signalSessionDatabase = signalSessionDatabase;
    }

    @Override
    public SessionRecord loadSession(SignalProtocolAddress address) {
        synchronized (LOCK) {
            return signalSessionDatabase.load(address).orElse(new SessionRecord());
        }
    }

    @Override
    public List<Integer> getSubDeviceSessions(String name) {
        synchronized (LOCK) {
            return signalSessionDatabase.getSubDeviceSessions(name);
        }
    }

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

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        synchronized (LOCK) {
            return signalSessionDatabase.load(address).isPresent();
        }
    }

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        synchronized (LOCK) {
            signalSessionDatabase.delete(address);
        }
    }

    @Override
    public void deleteAllSessions(String name) {
        synchronized (LOCK) {
            signalSessionDatabase.deleteAll(name);
        }
    }

}
