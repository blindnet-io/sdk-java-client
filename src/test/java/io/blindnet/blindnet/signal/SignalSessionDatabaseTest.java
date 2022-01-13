package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.internal.Database;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.SessionRecord;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignalSessionDatabaseTest extends SignalAbstractTest {

    private SignalSessionDatabase signalSessionDatabase;

    @Before
    public void setup() {
        Database.getInstance().executeStatement("drop table if exists 'session';");
        signalSessionDatabase = new SignalSessionDatabase();
    }

    @Test
    @DisplayName("Test storing of session.")
    public void testStoringOfSession() {
        String name = UUID.randomUUID().toString();
        int deviceId = 123;
        SignalProtocolAddress address = new SignalProtocolAddress(name, deviceId);
        SessionRecord sessionRecord = new SessionRecord();

        signalSessionDatabase.store(address, sessionRecord);
        Optional<SessionRecord> savedSessionRecord = signalSessionDatabase.load(address);

        assertTrue(savedSessionRecord.isPresent());
    }

    @Test
    @DisplayName("Test loading of sub device sessions.")
    public void testStoringOfSubDeviceSessions() {
        String name = UUID.randomUUID().toString();
        int deviceId = 123;
        SignalProtocolAddress address = new SignalProtocolAddress(name, deviceId);
        SessionRecord sessionRecord = new SessionRecord();

        signalSessionDatabase.store(address, sessionRecord);
        List<Integer> deviceIds = signalSessionDatabase.getSubDeviceSessions(name);

        assertEquals(deviceIds.size(), 1);
        assertEquals(deviceIds.get(0), deviceId);
    }

    @Test
    @DisplayName("Test deleting of session.")
    public void testDeletingOfSession() {
        String name = UUID.randomUUID().toString();
        int deviceId = 123;
        SignalProtocolAddress address = new SignalProtocolAddress(name, deviceId);
        SessionRecord sessionRecord = new SessionRecord();

        signalSessionDatabase.store(address, sessionRecord);
        signalSessionDatabase.delete(address);
        Optional<SessionRecord> savedSessionRecord = signalSessionDatabase.load(address);

        assertTrue(savedSessionRecord.isEmpty());
    }

    @Test
    @DisplayName("Test deleting of all sessions.")
    public void testDeletingOfAllSessions() {
        String name = UUID.randomUUID().toString();
        int deviceIdOne = 123;
        SignalProtocolAddress addressOne = new SignalProtocolAddress(name, deviceIdOne);
        int deviceIdTwo = 321;
        SignalProtocolAddress addressTwo = new SignalProtocolAddress(name, deviceIdTwo);

        signalSessionDatabase.store(addressOne, new SessionRecord());
        signalSessionDatabase.store(addressTwo, new SessionRecord());

        signalSessionDatabase.deleteAll(name);
        Optional<SessionRecord> savedSessionRecordOne = signalSessionDatabase.load(addressOne);
        assertTrue(savedSessionRecordOne.isEmpty());
        Optional<SessionRecord> savedSessionRecordTwo = signalSessionDatabase.load(addressOne);
        assertTrue(savedSessionRecordTwo.isEmpty());
    }

}
