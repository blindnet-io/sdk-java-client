package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.StorageException;
import io.blindnet.blindnet.internal.Database;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;

import java.sql.*;
import java.util.Optional;

/**
 * Database API used for storing of identities and identity keys.
 */
class SignalIdentityDatabase {

    private static final String LOCAL_IDENTITY_TABLE_NAME = "local_identity";
    private static final String LOCAL_REGISTRATION_ID_COLUMN = "registration_id";
    private static final String LOCAL_DEVICE_ID = "device_id";
    private static final String LOCAL_PRIVATE_KEY_COLUMN = "private_key";
    private static final String LOCAL_PUBLIC_KEY_COLUMN = "public_key";

    private static final String IDENTITY_TABLE_NAME = "identity";
    private static final String NAME_COLUMN = "name";
    private static final String DEVICE_ID_COLUMN = "device_id";
    private static final String IDENTITY_KEY_COLUMN = "identity_key";

    private static final String INSERT_LOCAL_IDENTITY_STATEMENT = "INSERT INTO local_identity (registration_id, device_id, private_key, public_key) VALUES(?, ?, ?, ?)";
    private static final String SELECT_LOCAL_IDENTITY_STATEMENT = "SELECT registration_id, private_key, public_key FROM local_identity";
    private static final String SELECT_REGISTRATION_ID_STATEMENT = "SELECT registration_id FROM local_identity";
    private static final String SELECT_DEVICE_ID_STATEMENT = "SELECT device_id FROM local_identity";
    private static final String DELETE_LOCAL_IDENTITY_STATEMENT = "DELETE FROM local_identity WHERE 1=1";

    private static final String INSERT_IDENTITY_STATEMENT = "INSERT INTO identity (name, device_id, identity_key) VALUES(?, ?, ?)";
    private static final String SELECT_IDENTITY_STATEMENT = "SELECT identity_key FROM identity WHERE name = ? AND device_id = ?";
    private static final String DELETE_IDENTITY_STATEMENT = "DELETE FROM identity WHERE name = ? AND device_id = ?";

    private final Database database;

    public SignalIdentityDatabase() {
        database = Database.getInstance();
        init();
    }

    /**
     * Stores identity key pair.
     *
     * @param registrationId an id of the registration.
     * @param deviceId an id of the device.
     * @param identityKeyPair an identity key pair object.
     */
    public void saveLocalIdentity(int registrationId, int deviceId, IdentityKeyPair identityKeyPair) {
        deleteLocalIdentity();

        try (Connection conn = database.connect();
             PreparedStatement statement = conn.prepareStatement(INSERT_LOCAL_IDENTITY_STATEMENT)) {
            statement.setInt(1, registrationId);
            statement.setInt(2, deviceId);
            statement.setBytes(3, identityKeyPair.getPrivateKey().serialize());
            statement.setBytes(4, identityKeyPair.getPublicKey().getPublicKey().serialize());
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to store local identity key pair.");
        }
    }

    /**
     * Reads identity key pair.
     *
     * @return an identity key pair object.
     */
    public IdentityKeyPair readLocalIdentity() {
        try (Connection conn = database.connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(SELECT_LOCAL_IDENTITY_STATEMENT)) {

            // there should be only one local identity
            if (rs.next()) {
                return new IdentityKeyPair(new IdentityKey(rs.getBytes(LOCAL_PUBLIC_KEY_COLUMN), 0),
                        Curve.decodePrivatePoint(rs.getBytes(LOCAL_PRIVATE_KEY_COLUMN)));
            }
            return null;
        } catch (SQLException | InvalidKeyException e) {
            throw new StorageException("Unable to read local identity key pair.");
        }
    }

    /**
     * Reads the id of the registration.
     *
     * @return an id of the registration.
     */
    public int readLocalRegistrationId() {
        try (Connection conn = database.connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(SELECT_REGISTRATION_ID_STATEMENT)) {

            // there should be only one identity
            if (rs.next()) {
                return rs.getInt(LOCAL_REGISTRATION_ID_COLUMN);
            }
            return -1;
        } catch (SQLException e) {
            throw new StorageException("Unable to read registration id.");
        }
    }

    /**
     * Reads the id of the local device.
     *
     * @return an id of the local device.
     */
    public int readLocalDeviceId() {
        try (Connection conn = database.connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(SELECT_DEVICE_ID_STATEMENT)) {

            // there should be only one identity
            if (rs.next()) {
                return rs.getInt(LOCAL_DEVICE_ID);
            }
            return -1;
        } catch (SQLException e) {
            throw new StorageException("Unable to read local device id.");
        }
    }

    /**
     * Deletes local identity key pair.
     */
    public void deleteLocalIdentity() {
        try (Connection conn = database.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_LOCAL_IDENTITY_STATEMENT)) {
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to delete local identity key pair.");
        }
    }

    /**
     * Stores identity key and corresponding signal address.
     *
     * @param address a signal address.
     * @param identityKey an identity key to be stored.
     */
    public void saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        try (Connection conn = database.connect();
             PreparedStatement statement = conn.prepareStatement(INSERT_IDENTITY_STATEMENT)) {

            statement.setString(1, address.getName());
            statement.setInt(2, address.getDeviceId());
            statement.setBytes(3, identityKey.serialize());
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to store identity key.");
        }
    }

    /**
     * Read identity key based on provided address.
     *
     * @param address a signal address.
     * @return an optional wrapper of identity key.
     */
    public Optional<IdentityKey> readIdentity(SignalProtocolAddress address) {
        try (Connection conn = database.connect();
             PreparedStatement statement = conn.prepareStatement(SELECT_IDENTITY_STATEMENT)) {

            statement.setString(1, address.getName());
            statement.setInt(2, address.getDeviceId());
            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                return Optional.of(new IdentityKey(rs.getBytes(IDENTITY_KEY_COLUMN), 0));
            }
            return Optional.empty();
        } catch (SQLException | InvalidKeyException e) {
            throw new StorageException("Unable to read identity key.");
        }
    }

    /**
     * Deletes identity key based on provided address.
     *
     * @param address a signal address.
     */
    public void deleteIdentity(SignalProtocolAddress address) {
        try (Connection conn = database.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_IDENTITY_STATEMENT)) {

            stmt.setString(1, address.getName());
            stmt.setInt(2, address.getDeviceId());
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to delete identity key.");
        }
    }

    /**
     * Initialization method that creates local_identity and identity tables.
     */
    private void init() {
        String createLocalIdentityTableCmd = "CREATE TABLE IF NOT EXISTS " + LOCAL_IDENTITY_TABLE_NAME + " (\n"
                + LOCAL_REGISTRATION_ID_COLUMN + " integer NOT NULL,\n"
                + LOCAL_DEVICE_ID + " integer NOT NULL,\n"
                + LOCAL_PRIVATE_KEY_COLUMN + " blob NOT NULL,\n"
                + LOCAL_PUBLIC_KEY_COLUMN + "	blob NOT NULL\n"
                + ");";
        database.executeStatement(createLocalIdentityTableCmd);

        String createIdentityTableCmd = "CREATE TABLE IF NOT EXISTS " + IDENTITY_TABLE_NAME + " (\n"
                + NAME_COLUMN + " text NOT NULL,\n"
                + DEVICE_ID_COLUMN + " integer NOT NULL,\n"
                + IDENTITY_KEY_COLUMN + "	blob NOT NULL,\n"
                + "UNIQUE(" + DEVICE_ID_COLUMN + "," + NAME_COLUMN + ")\n"
                + ");";

        database.executeStatement(createIdentityTableCmd);
    }

}
