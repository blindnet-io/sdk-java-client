package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.StorageException;
import io.blindnet.blindnet.internal.Database;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class SignalSignedPreKeyDatabaseTest extends SignalAbstractTest {

    private SignalSignedPreKeyDatabase signalSignedPreKeyDatabase;

    @Before
    public void setup() {
        Database.getInstance().executeStatement("drop table if exists 'signed_pre_key';");
        signalSignedPreKeyDatabase = new SignalSignedPreKeyDatabase();
    }

    @Test
    @DisplayName("Test storing of signed pre key.")
    public void testStoringOfPreKey() throws InvalidKeyException {
        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
        SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, new SecureRandom().nextInt());

        signalSignedPreKeyDatabase.store(signedPreKey.getId(), signedPreKey);

        Optional<SignedPreKeyRecord> savedSignedPreKey = signalSignedPreKeyDatabase.load(signedPreKey.getId());

        assertTrue(savedSignedPreKey.isPresent());
        assertEquals(new String(signedPreKey.serialize()), new String(savedSignedPreKey.get().serialize()));
    }

    @Test
    @DisplayName("Test storing of signed pre key with invalid id.")
    public void testStoringOfPreKey_thenInvalidId() throws InvalidKeyException {
        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
        SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, new SecureRandom().nextInt());

        signalSignedPreKeyDatabase.store(signedPreKey.getId(), signedPreKey);

        SignedPreKeyRecord duplicateSignedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, new SecureRandom().nextInt());
        StorageException storePreKeyException = assertThrows(StorageException.class,
                () -> signalSignedPreKeyDatabase.store(signedPreKey.getId(), duplicateSignedPreKey));
        assertTrue(storePreKeyException.getMessage().contains("Unable to store signed pre key"));
    }

    @Test
    @DisplayName("Test storing of multiple signed pre keys.")
    public void testStoringOfMultiplePreKey() throws InvalidKeyException {
        IdentityKeyPair identityKeyPairOne = KeyHelper.generateIdentityKeyPair();
        SignedPreKeyRecord signedPreKeyOne = KeyHelper.generateSignedPreKey(identityKeyPairOne, new SecureRandom().nextInt());
        signalSignedPreKeyDatabase.store(signedPreKeyOne.getId(), signedPreKeyOne);

        IdentityKeyPair identityKeyPairTwo = KeyHelper.generateIdentityKeyPair();
        SignedPreKeyRecord signedPreKeyTwo = KeyHelper.generateSignedPreKey(identityKeyPairTwo, new SecureRandom().nextInt());
        signalSignedPreKeyDatabase.store(signedPreKeyTwo.getId(), signedPreKeyTwo);

        List<SignedPreKeyRecord> signedPreKeys = signalSignedPreKeyDatabase.loadRecords();

        assertEquals(signedPreKeys.size(), 2);
        assertEquals(signedPreKeys.get(0).getId(), signedPreKeyOne.getId());
        assertEquals(signedPreKeys.get(1).getId(), signedPreKeyTwo.getId());
        assertEquals(new String(signedPreKeys.get(0).serialize()), new String(signedPreKeyOne.serialize()));
        assertEquals(new String(signedPreKeys.get(1).serialize()), new String(signedPreKeyTwo.serialize()));
    }

    @Test
    @DisplayName("Test deleting of signed pre key.")
    public void testDeletingOfPreKey() throws InvalidKeyException {
        IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
        SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, new SecureRandom().nextInt());

        signalSignedPreKeyDatabase.store(signedPreKey.getId(), signedPreKey);
        signalSignedPreKeyDatabase.delete(signedPreKey.getId());
        Optional<SignedPreKeyRecord> savedSignedPreKey = signalSignedPreKeyDatabase.load(signedPreKey.getId());
        assertTrue(savedSignedPreKey.isEmpty());
    }

}
