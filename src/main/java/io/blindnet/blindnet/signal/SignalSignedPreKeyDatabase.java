package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.internal.DatabaseService;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class SignalSignedPreKeyDatabase {

    private final DatabaseService databaseService;

    private static final String SIGNED_PRE_KEY_TABLE_NAME = "signed_pre_key";
    private static final String SIGNED_PRE_KEY_ID_COLUMN = "signed_pre_key_id";
    private static final String SIGNED_PRE_KEY_RECORD = "signed_pre_key_record";

    private static final String INSERT_SIGNED_PRE_KEY_STATEMENT = "INSERT INTO signed_pre_key (signed_pre_key_id, signed_pre_key_record) VALUES(?, ?)";
    private static final String SELECT_SIGNED_PRE_KEY_STATEMENT = "SELECT signed_pre_key_record FROM signed_pre_key WHERE signed_pre_key_id = ?";
    private static final String SELECT_ALL_SIGNED_PRE_KEYS_STATEMENT = "SELECT signed_pre_key_record FROM signed_pre_key";
    private static final String DELETE_SIGNED_PRE_KEY_STATEMENT = "DELETE FROM signed_pre_key WHERE signed_pre_key_id = ?";

    // todo refactor repeated parts

    public SignalSignedPreKeyDatabase(DatabaseService databaseService) {
        this.databaseService = databaseService;
        init();
    }

    public void store(int signedPreKeyId, SignedPreKeyRecord signedPreKeyRecord) {
        try (Connection conn = databaseService.connect();
             PreparedStatement statement = conn.prepareStatement(INSERT_SIGNED_PRE_KEY_STATEMENT)) {

            statement.setInt(1, signedPreKeyId);
            statement.setBytes(2, signedPreKeyRecord.serialize());
            statement.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public Optional<SignedPreKeyRecord> load(int signedPreKeyId) {
        try (Connection conn = databaseService.connect();
             PreparedStatement statement  = conn.prepareStatement(SELECT_SIGNED_PRE_KEY_STATEMENT)) {

            statement.setInt(1, signedPreKeyId);
            ResultSet rs  = statement.executeQuery();

            if (rs.next()) {
                return Optional.of(new SignedPreKeyRecord(rs.getBytes(SIGNED_PRE_KEY_RECORD)));
            }
            return Optional.empty();
        } catch (SQLException | IOException e) {
            System.out.println(e.getMessage());
            return Optional.empty();
        }
    }

    public List<SignedPreKeyRecord> loadRecords() {
        try (Connection conn = databaseService.connect();
             Statement stmt  = conn.createStatement();
             ResultSet rs    = stmt.executeQuery(SELECT_ALL_SIGNED_PRE_KEYS_STATEMENT)){

            List<SignedPreKeyRecord> result = new ArrayList<>();
            // loop through the result set
            while (rs.next()) {
                result.add(new SignedPreKeyRecord(rs.getBytes(SIGNED_PRE_KEY_RECORD)));
            }
            return result;
        } catch (SQLException | IOException e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public void delete(int signedPreKeyId) {
        try (Connection conn = databaseService.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_SIGNED_PRE_KEY_STATEMENT)) {

            stmt.setInt(1, signedPreKeyId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    private void init() {
        String createSessionTableCmd = "CREATE TABLE IF NOT EXISTS " + SIGNED_PRE_KEY_TABLE_NAME + " (\n"
                + SIGNED_PRE_KEY_ID_COLUMN + " integer NOT NULL,\n"
                + SIGNED_PRE_KEY_RECORD + "	blob NOT NULL,\n"
                + "UNIQUE(" + SIGNED_PRE_KEY_ID_COLUMN + ")\n"
                + ");";

        databaseService.createTable(createSessionTableCmd);
    }

}
