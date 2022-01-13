package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.StorageException;
import io.blindnet.blindnet.internal.Database;
import org.whispersystems.libsignal.state.PreKeyRecord;

import java.io.IOException;
import java.sql.*;
import java.util.Optional;

/**
 * Database API used for storing of signed pre keys.
 */
class SignalPreKeyDatabase {

    private static final String PRE_KEY_TABLE_NAME = "pre_key";
    private static final String PRE_KEY_ID_COLUMN = "pre_key_id";
    private static final String PRE_KEY_RECORD = "pre_key_record";

    private static final String INSERT_PRE_KEY_STATEMENT = "INSERT INTO pre_key (pre_key_id, pre_key_record) VALUES(?, ?)";
    private static final String READ_PRE_KEY_STATEMENT = "SELECT pre_key_record FROM pre_key WHERE pre_key_id = ?";
    private static final String COUNT_PRE_KEYS_STATEMENT = "SELECT COUNT(*) AS rowcount FROM pre_key";
    private static final String DELETE_PRE_KEY_STATEMENT = "DELETE FROM pre_key WHERE pre_key_id = ?";

    private final Database database;

    public SignalPreKeyDatabase() {
        database = Database.getInstance();
        init();
    }

    /**
     * Stores a pre key.
     *
     * @param preKeyId an id of the pre key.
     * @param preKeyRecord a pre key record.
     */
    public void store(int preKeyId, PreKeyRecord preKeyRecord) {
        try (Connection conn = database.connect();
             PreparedStatement statement = conn.prepareStatement(INSERT_PRE_KEY_STATEMENT)) {

            statement.setInt(1, preKeyId);
            statement.setBytes(2, preKeyRecord.serialize());
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to store a pre key.");
        }
    }

    /**
     * Loads a pre key based on id.
     *
     * @param preKeyId an id of the pre key.
     * @return an optional wrapper of pre key record.
     */
    public Optional<PreKeyRecord> load(int preKeyId) {
        try (Connection conn = database.connect();
             PreparedStatement statement  = conn.prepareStatement(READ_PRE_KEY_STATEMENT)) {

            statement.setInt(1, preKeyId);
            ResultSet rs  = statement.executeQuery();

            if (rs.next()) {
                return Optional.of(new PreKeyRecord(rs.getBytes(PRE_KEY_RECORD)));
            }
            return Optional.empty();
        } catch (SQLException | IOException e) {
            throw new StorageException("Unable to load pre key for id: " + preKeyId);
        }
    }

    /**
     * Counts number of pre keys in the database.
     *
     * @return a number of pre keys.
     */
    public int countPreKeys() {
        try (Connection conn = database.connect();
             Statement stmt  = conn.createStatement();
             ResultSet rs    = stmt.executeQuery(COUNT_PRE_KEYS_STATEMENT)){

            if (rs.next()) {
                return rs.getInt("rowcount");
            }
            return 0;
        } catch (SQLException e) {
            throw new StorageException("Unable to count number of pre keys in the database.");
        }
    }

    /**
     * Deletes a pre key based on id.
     *
     * @param preKeyId an id of the pre key.
     */
    public void delete(int preKeyId) {
        try (Connection conn = database.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_PRE_KEY_STATEMENT)) {

            stmt.setInt(1, preKeyId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to delete a pre key for id: " + preKeyId);
        }
    }

    /**
     * Initialization method that creates pre_key table.
     */
    private void init() {
        String createSessionTableCmd = "CREATE TABLE IF NOT EXISTS " + PRE_KEY_TABLE_NAME + " (\n"
                + PRE_KEY_ID_COLUMN + " integer NOT NULL,\n"
                + PRE_KEY_RECORD + "	blob NOT NULL,\n"
                + "UNIQUE(" + PRE_KEY_ID_COLUMN + ")\n"
                + ");";

        database.executeStatement(createSessionTableCmd);
    }

}
