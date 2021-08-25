package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.internal.DatabaseConfig;
import io.blindnet.blindnet.internal.DatabaseService;
import org.junit.Before;
import org.junit.Test;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class SignalSessionDatabaseTest {

    private DatabaseService databaseService;
    private SignalSessionDatabase signalSessionDatabase;

    @Before
    public void setup() {
        DatabaseConfig.INSTANCE.setup(System.getProperty("java.io.tmpdir"));
        signalSessionDatabase = new SignalSessionDatabase(new DatabaseService());
    }

    @Test
    public void testStoringOfLocalIdentityKey() {
        String name = UUID.randomUUID().toString();
        int deviceId = 123;
        SignalProtocolAddress address = new SignalProtocolAddress(name, deviceId);

        SessionRecord sessionRecord = new SessionRecord();

        signalSessionDatabase.store(address, sessionRecord);
        Optional<SessionRecord> savedSessionRecord = signalSessionDatabase.load(address);

        assertTrue(savedSessionRecord.isPresent());
//        assertNotNull(savedIdentityKey);
//        assertNotNull(savedRegistrationId);
//        assertArrayEquals(identityKeyPair.serialize(), savedIdentityKey.serialize());
//        assertArrayEquals(identityKeyPair.getPublicKey().serialize(),
//                savedIdentityKey.getPublicKey().serialize());
//        assertArrayEquals(identityKeyPair.getPrivateKey().serialize(),
//                savedIdentityKey.getPrivateKey().serialize());
//        assertEquals(registrationId, savedRegistrationId);
    }

}
