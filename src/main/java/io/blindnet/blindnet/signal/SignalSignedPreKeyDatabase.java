package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.StorageException;
import io.blindnet.blindnet.internal.Database;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Database API used for storing of signed pre keys.
 */
class SignalSignedPreKeyDatabase {

    private static final String SIGNED_PRE_KEY_TABLE_NAME = "signed_pre_key";
    private static final String SIGNED_PRE_KEY_ID_COLUMN = "signed_pre_key_id";
    private static final String SIGNED_PRE_KEY_RECORD = "signed_pre_key_record";

    private static final String INSERT_SIGNED_PRE_KEY_STATEMENT = "INSERT INTO signed_pre_key (signed_pre_key_id, signed_pre_key_record) VALUES(?, ?)";
    private static final String SELECT_SIGNED_PRE_KEY_STATEMENT = "SELECT signed_pre_key_record FROM signed_pre_key WHERE signed_pre_key_id = ?";
    private static final String SELECT_ALL_SIGNED_PRE_KEYS_STATEMENT = "SELECT signed_pre_key_record FROM signed_pre_key";
    private static final String DELETE_SIGNED_PRE_KEY_STATEMENT = "DELETE FROM signed_pre_key WHERE signed_pre_key_id = ?";

    private final Database database;

    public SignalSignedPreKeyDatabase() {
        database = Database.getInstance();
        init();
    }

    /**
     * Stores signed pre key.
     *
     * @param signedPreKeyId an id of signed pre key.
     * @param signedPreKeyRecord a signed pre key.
     */
    public void store(int signedPreKeyId, SignedPreKeyRecord signedPreKeyRecord) {
        try (Connection conn = database.connect();
             PreparedStatement statement = conn.prepareStatement(INSERT_SIGNED_PRE_KEY_STATEMENT)) {

            statement.setInt(1, signedPreKeyId);
            statement.setBytes(2, signedPreKeyRecord.serialize());
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to store signed pre key.");
        }
    }

    /**
     * Loads signed pre key based on id.
     *
     * @param signedPreKeyId an id of signed pre key.
     * @return an optional wrapper of signed pre key object.
     */
    public Optional<SignedPreKeyRecord> load(int signedPreKeyId) {
        try (Connection conn = database.connect();
             PreparedStatement statement  = conn.prepareStatement(SELECT_SIGNED_PRE_KEY_STATEMENT)) {

            statement.setInt(1, signedPreKeyId);
            ResultSet rs  = statement.executeQuery();

            if (rs.next()) {
                return Optional.of(new SignedPreKeyRecord(rs.getBytes(SIGNED_PRE_KEY_RECORD)));
            }
            return Optional.empty();
        } catch (SQLException | IOException e) {
            throw new StorageException("Unable to read signed pre key for id: " + signedPreKeyId);
        }
    }

    /**
     * Loads all signed pre keys.
     *
     * @return a list of signed pre key records.
     */
    public List<SignedPreKeyRecord> loadRecords() {
        try (Connection conn = database.connect();
             Statement stmt  = conn.createStatement();
             ResultSet rs    = stmt.executeQuery(SELECT_ALL_SIGNED_PRE_KEYS_STATEMENT)){

            List<SignedPreKeyRecord> result = new ArrayList<>();
            while (rs.next()) {
                result.add(new SignedPreKeyRecord(rs.getBytes(SIGNED_PRE_KEY_RECORD)));
            }
            return result;
        } catch (SQLException | IOException e) {
            throw new StorageException("Unable to read signed pre key records.");
        }
    }

    /**
     * Deletes signed pre key based on id.
     *
     * @param signedPreKeyId an id of signed pre key.
     */
    public void delete(int signedPreKeyId) {
        try (Connection conn = database.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_SIGNED_PRE_KEY_STATEMENT)) {

            stmt.setInt(1, signedPreKeyId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to delete signed pre key.");
        }
    }

    /**
     * Initialization method that creates signed_pre_key table.
     */
    private void init() {
        String createSessionTableCmd = "CREATE TABLE IF NOT EXISTS " + SIGNED_PRE_KEY_TABLE_NAME + " (\n"
                + SIGNED_PRE_KEY_ID_COLUMN + " integer NOT NULL,\n"
                + SIGNED_PRE_KEY_RECORD + "	blob NOT NULL,\n"
                + "UNIQUE(" + SIGNED_PRE_KEY_ID_COLUMN + ")\n"
                + ");";

        database.executeStatement(createSessionTableCmd);
    }

}
