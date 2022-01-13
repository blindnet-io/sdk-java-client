package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.internal.Database;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.util.KeyHelper;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.*;

public class SignalIdentityDatabaseTest extends SignalAbstractTest {

    private SignalIdentityDatabase signalIdentityDatabase;

    @Before
    public void setup() {
        Database.getInstance().executeStatement("drop table if exists 'local_identity';");
        Database.getInstance().executeStatement("drop table if exists 'identity';");
        signalIdentityDatabase = new SignalIdentityDatabase();
    }

    @Test
    @DisplayName("Test storing of local identity key.")
    public void testStoringOfLocalIdentityKey() {
        int registrationId = KeyHelper.generateRegistrationId(false);
        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
        int deviceId = ThreadLocalRandom.current().nextInt();

        signalIdentityDatabase.saveLocalIdentity(registrationId, deviceId, identityKeyPair);
        IdentityKeyPair savedIdentityKey = signalIdentityDatabase.readLocalIdentity();
        int savedRegistrationId = signalIdentityDatabase.readLocalRegistrationId();
        int savedDeviceId = signalIdentityDatabase.readLocalDeviceId();

        assertNotNull(savedIdentityKey);
        assertArrayEquals(identityKeyPair.serialize(), savedIdentityKey.serialize());
        assertArrayEquals(identityKeyPair.getPublicKey().serialize(),
                savedIdentityKey.getPublicKey().serialize());
        assertArrayEquals(identityKeyPair.getPrivateKey().serialize(),
                savedIdentityKey.getPrivateKey().serialize());
        assertEquals(registrationId, savedRegistrationId);
        assertEquals(deviceId, savedDeviceId);
    }

    @Test
    @DisplayName("Test storing of identity.")
    public void testStoringOfIdentity() {
        String name = UUID.randomUUID().toString();
        int deviceId = 123;
        IdentityKey identityKey = KeyHelper.generateIdentityKeyPair().getPublicKey();
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(name, deviceId);

        signalIdentityDatabase.saveIdentity(signalProtocolAddress, identityKey);
        Optional<IdentityKey> optionalIdentityKey = signalIdentityDatabase.readIdentity(signalProtocolAddress);

        assertTrue(optionalIdentityKey.isPresent());
        assertArrayEquals(identityKey.serialize(), optionalIdentityKey.get().serialize());
    }

    @Test
    @DisplayName("Test deleting of identity.")
    public void testDeletingOfIdentity() {
        String name = UUID.randomUUID().toString();
        int deviceId = 123;
        IdentityKey identityKey = KeyHelper.generateIdentityKeyPair().getPublicKey();
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(name, deviceId);

        signalIdentityDatabase.saveIdentity(signalProtocolAddress, identityKey);
        signalIdentityDatabase.deleteIdentity(signalProtocolAddress);
        Optional<IdentityKey> optionalIdentityKey = signalIdentityDatabase.readIdentity(signalProtocolAddress);

        assertTrue(optionalIdentityKey.isEmpty());
    }

}
