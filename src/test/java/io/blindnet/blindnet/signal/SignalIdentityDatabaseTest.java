package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.internal.DatabaseConfig;
import io.blindnet.blindnet.internal.DatabaseService;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.File;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.*;

public class SignalIdentityDatabaseTest {

    private SignalIdentityDatabase signalIdentityDatabase;

    @Before
    public void setup() {
        DatabaseConfig.INSTANCE.setup(System.getProperty("java.io.tmpdir"));
        signalIdentityDatabase = new SignalIdentityDatabase(new DatabaseService());
    }

    @Test
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

    // TODO refactor
    @AfterClass
    public static void classCleanup() {
        deleteFolder(new File(DatabaseService.URL));
    }

    private static void deleteFolder(File folder) {
        File[] files = folder.listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.isDirectory()) {
                    deleteFolder(f);
                } else {
                    f.delete();
                }
            }
        }
        folder.delete();
    }
}
