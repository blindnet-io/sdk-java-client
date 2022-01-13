package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.KeyGenerationException;
import io.blindnet.blindnet.exception.StorageException;
import io.blindnet.blindnet.internal.Database;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class SignalPreKeyDatabaseTest extends SignalAbstractTest {

    private SignalPreKeyDatabase signalPreKeyDatabase;

    @Before
    public void setup() {
        Database.getInstance().executeStatement("drop table if exists 'pre_key';");
        signalPreKeyDatabase = new SignalPreKeyDatabase();
    }

    @Test
    @DisplayName("Test storing of pre key.")
    public void testStoringOfPreKey() {
        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(111, 2);

        signalPreKeyDatabase.store(preKeys.get(0).getId(), preKeys.get(0));
        signalPreKeyDatabase.store(preKeys.get(1).getId(), preKeys.get(1));

        Optional<PreKeyRecord> loadedPreKey = signalPreKeyDatabase.load(preKeys.get(0).getId());

        assertTrue(loadedPreKey.isPresent());
        assertEquals(new String(loadedPreKey.get().serialize()), new String(preKeys.get(0).serialize()));
    }

    @Test
    @DisplayName("Test storing of pre key with invalid pre key id.")
    public void testStoringOfPreKey_thenInvalidPreKeyId() {
        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(111, 2);

        signalPreKeyDatabase.store(preKeys.get(0).getId(), preKeys.get(0));
        signalPreKeyDatabase.store(preKeys.get(1).getId(), preKeys.get(1));

        List<PreKeyRecord> duplicates = KeyHelper.generatePreKeys(111, 1);
        StorageException storePreKeyException = assertThrows(StorageException.class,
                () -> signalPreKeyDatabase.store(duplicates.get(0).getId(), duplicates.get(0)));
        assertTrue(storePreKeyException.getMessage().contains("Unable to store a pre key"));
    }

    @Test
    @DisplayName("Test reading of not existing pre key.")
    public void testReadingOfPreKey_thenNotExistingPreKey() {
        Optional<PreKeyRecord> loadedPreKey = signalPreKeyDatabase.load(1);
        assertTrue(loadedPreKey.isEmpty());
    }

    @Test
    @DisplayName("Test counting of pre keys.")
    public void testCountingOfPreKeys() {
        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(5, 2);

        signalPreKeyDatabase.store(preKeys.get(0).getId(), preKeys.get(0));
        signalPreKeyDatabase.store(preKeys.get(1).getId(), preKeys.get(1));

        int numberOfPreKeys = signalPreKeyDatabase.countPreKeys();
        assertEquals(numberOfPreKeys, 2);
    }

    @Test
    @DisplayName("Test counting of pre keys.")
    public void testCountingOfPreKeys_whenNoPreKeys() {
        int numberOfPreKeys = signalPreKeyDatabase.countPreKeys();
        assertEquals(numberOfPreKeys, 0);
    }

    @Test
    @DisplayName("Test deleting of pre key.")
    public void testDeletingOfPreKey() {
        List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(7, 2);

        signalPreKeyDatabase.store(preKeys.get(0).getId(), preKeys.get(0));
        signalPreKeyDatabase.store(preKeys.get(1).getId(), preKeys.get(1));

        signalPreKeyDatabase.delete(preKeys.get(0).getId());

        Optional<PreKeyRecord> deletedPreKey = signalPreKeyDatabase.load(preKeys.get(0).getId());
        assertTrue(deletedPreKey.isEmpty());

        Optional<PreKeyRecord> existingPreKey = signalPreKeyDatabase.load(preKeys.get(1).getId());
        assertTrue(existingPreKey.isPresent());
    }

}
