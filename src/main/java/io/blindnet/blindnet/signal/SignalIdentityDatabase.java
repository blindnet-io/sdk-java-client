package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.internal.DatabaseService;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;

import java.sql.*;
import java.util.Optional;

public class SignalIdentityDatabase {

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

    private final DatabaseService databaseService;

    // todo; exception handling, java doc

    public SignalIdentityDatabase(DatabaseService databaseService) {
        this.databaseService = databaseService;
        init();
    }

    public void saveLocalIdentity(int registrationId, int deviceId, IdentityKeyPair identityKeyPair) {
        // todo check this and check unique constraint
        // todo there should be only one local identity
        deleteLocalIdentity();

        try (Connection conn = databaseService.connect();
             PreparedStatement statement = conn.prepareStatement(INSERT_LOCAL_IDENTITY_STATEMENT)) {
            statement.setInt(1, registrationId);
            statement.setInt(2, deviceId);
            statement.setBytes(3, identityKeyPair.getPrivateKey().serialize());
            statement.setBytes(4, identityKeyPair.getPublicKey().getPublicKey().serialize());
            statement.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public IdentityKeyPair readLocalIdentity() {
        try (Connection conn = databaseService.connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(SELECT_LOCAL_IDENTITY_STATEMENT)) {

            // there should be only one local identity
            if (rs.next()) {
                return new IdentityKeyPair(new IdentityKey(rs.getBytes(LOCAL_PUBLIC_KEY_COLUMN), 0),
                        Curve.decodePrivatePoint(rs.getBytes(LOCAL_PRIVATE_KEY_COLUMN)));
            }
            return null;
        } catch (SQLException | InvalidKeyException e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public int readLocalRegistrationId() {
        try (Connection conn = databaseService.connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(SELECT_REGISTRATION_ID_STATEMENT)) {

            // there should be only one identity
            if (rs.next()) {
                return rs.getInt(LOCAL_REGISTRATION_ID_COLUMN);
            }
            return -1;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return -1;
        }
    }

    public int readLocalDeviceId() {
        try (Connection conn = databaseService.connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(SELECT_DEVICE_ID_STATEMENT)) {

            // there should be only one identity
            if (rs.next()) {
                return rs.getInt(LOCAL_DEVICE_ID);
            }
            return -1;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return -1;
        }
    }

    public void deleteLocalIdentity() {
        try (Connection conn = databaseService.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_LOCAL_IDENTITY_STATEMENT)) {

            stmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        try (Connection conn = databaseService.connect();
             PreparedStatement statement = conn.prepareStatement(INSERT_IDENTITY_STATEMENT)) {

            statement.setString(1, address.getName());
            statement.setInt(2, address.getDeviceId());
            statement.setBytes(3, identityKey.serialize());
            statement.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public Optional<IdentityKey> readIdentity(SignalProtocolAddress address) {
        try (Connection conn = databaseService.connect();
             PreparedStatement statement  = conn.prepareStatement(SELECT_IDENTITY_STATEMENT)) {

            statement.setString(1, address.getName());
            statement.setInt(2, address.getDeviceId());
            ResultSet rs  = statement.executeQuery();

            if (rs.next()) {
                return Optional.of(new IdentityKey(rs.getBytes(IDENTITY_KEY_COLUMN), 0));
            }
            return Optional.empty();
        } catch (SQLException | InvalidKeyException e) {
            System.out.println(e.getMessage());
            return Optional.empty();
        }
    }

    public void deleteIdentity(SignalProtocolAddress address) {
        try (Connection conn = databaseService.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_IDENTITY_STATEMENT)) {

            stmt.setString(1, address.getName());
            stmt.setInt(2, address.getDeviceId());
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    private void init() {
        String createLocalIdentityTableCmd = "CREATE TABLE IF NOT EXISTS " + LOCAL_IDENTITY_TABLE_NAME + " (\n"
                + LOCAL_REGISTRATION_ID_COLUMN + " integer NOT NULL,\n"
                + LOCAL_DEVICE_ID + " integer NOT NULL,\n"
                + LOCAL_PRIVATE_KEY_COLUMN + " blob NOT NULL,\n"
                + LOCAL_PUBLIC_KEY_COLUMN + "	blob NOT NULL\n"
                + ");";
        databaseService.createTable(createLocalIdentityTableCmd);

        String createIdentityTableCmd = "CREATE TABLE IF NOT EXISTS " + IDENTITY_TABLE_NAME + " (\n"
                + NAME_COLUMN + " text NOT NULL,\n"
                + DEVICE_ID_COLUMN + " integer NOT NULL,\n"
                + IDENTITY_KEY_COLUMN + "	blob NOT NULL,\n"
                + "UNIQUE(" + DEVICE_ID_COLUMN + "," + NAME_COLUMN + ")\n"
                + ");";

        databaseService.createTable(createIdentityTableCmd);
    }

}
