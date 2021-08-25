package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.internal.DatabaseService;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class SignalPreKeyDatabase {

    private final DatabaseService databaseService;

    private static final String PRE_KEY_TABLE_NAME = "pre_key";
    private static final String PRE_KEY_ID_COLUMN = "pre_key_id";
    private static final String PRE_KEY_RECORD = "pre_key_record";

    private static final String INSERT_PRE_KEY_STATEMENT = "INSERT INTO pre_key (pre_key_id, pre_key_record) VALUES(?, ?)";
    private static final String READ_PRE_KEY_STATEMENT = "SELECT pre_key_record FROM pre_key WHERE pre_key_id = ?";
    private static final String COUNT_PRE_KEYS_STATEMENT = "SELECT COUNT(*) AS rowcount FROM pre_key";
    private static final String DELETE_PRE_KEY_STATEMENT = "DELETE FROM pre_key WHERE pre_key_id = ?";

    public SignalPreKeyDatabase(DatabaseService databaseService) {
        this.databaseService = databaseService;
        init();
    }

    public void store(int preKeyId, PreKeyRecord preKeyRecord) {
        try (Connection conn = databaseService.connect();
             PreparedStatement statement = conn.prepareStatement(INSERT_PRE_KEY_STATEMENT)) {

            statement.setInt(1, preKeyId);
            statement.setBytes(2, preKeyRecord.serialize());
            statement.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public Optional<PreKeyRecord> load(int preKeyId) {
        try (Connection conn = databaseService.connect();
             PreparedStatement statement  = conn.prepareStatement(READ_PRE_KEY_STATEMENT)) {

            statement.setInt(1, preKeyId);
            ResultSet rs  = statement.executeQuery();

            if (rs.next()) {
                return Optional.of(new PreKeyRecord(rs.getBytes(PRE_KEY_RECORD)));
            }
            return Optional.empty();
        } catch (SQLException | IOException e) {
            System.out.println(e.getMessage());
            return Optional.empty();
        }
    }

    public int countPreKeys() {
        try (Connection conn = databaseService.connect();
             Statement stmt  = conn.createStatement();
             ResultSet rs    = stmt.executeQuery(COUNT_PRE_KEYS_STATEMENT)){

            if (rs.next()) {
                rs.getInt("rowcount");
            }
            return 0;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return -1;
        }
    }

    public void delete(int preKeyId) {
        try (Connection conn = databaseService.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_PRE_KEY_STATEMENT)) {

            stmt.setInt(1, preKeyId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    private void init() {
        String createSessionTableCmd = "CREATE TABLE IF NOT EXISTS " + PRE_KEY_TABLE_NAME + " (\n"
                + PRE_KEY_ID_COLUMN + " integer NOT NULL,\n"
                + PRE_KEY_RECORD + "	blob NOT NULL,\n"
                + "UNIQUE(" + PRE_KEY_ID_COLUMN + ")\n"
                + ");";

        databaseService.createTable(createSessionTableCmd);
    }

}
