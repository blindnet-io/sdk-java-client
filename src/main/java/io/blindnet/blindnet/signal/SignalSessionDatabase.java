package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.internal.DatabaseService;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.SessionRecord;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class SignalSessionDatabase {

    private final DatabaseService databaseService;

    private static final String SESSION_TABLE_NAME = "session";
    private static final String NAME_COLUMN = "name";
    private static final String DEVICE_ID_COLUMN = "device_id";
    private static final String SESSION_RECORD_COLUMN = "session_record";

    private static final String INSERT_SESSION_STATEMENT = "INSERT INTO session (name, device_id, session_record) VALUES(?, ?, ?)";
    private static final String READ_SESSION_STATEMENT = "SELECT session_record FROM session WHERE name = ? AND device_id = ?";
    private static final String READ_SESSIONS_BY_NAME_STATEMENT = "SELECT device_id FROM session WHERE name = ?";
    private static final String DELETE_SESSION_STATEMENT = "DELETE FROM session WHERE name = ? AND device_id = ?";
    private static final String DELETE_ALL_SESSIONS_STATEMENT = "DELETE FROM session WHERE name = ?";

    // todo; refactor parts that are repeated, exception handling, java doc

    public SignalSessionDatabase(DatabaseService databaseService) {
        this.databaseService = databaseService;
        init();
    }

    // todo possible duplicate
    public void store(SignalProtocolAddress address, SessionRecord record) {
        try (Connection conn = databaseService.connect();
             PreparedStatement statement = conn.prepareStatement(INSERT_SESSION_STATEMENT)) {

            statement.setString(1, address.getName());
            statement.setInt(2, address.getDeviceId());
            statement.setBytes(3, record.serialize());
            statement.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public Optional<SessionRecord> load(SignalProtocolAddress address) {
        try (Connection conn = databaseService.connect();
             PreparedStatement statement  = conn.prepareStatement(READ_SESSION_STATEMENT)) {

            statement.setString(1, address.getName());
            statement.setInt(2, address.getDeviceId());
            ResultSet rs  = statement.executeQuery();

            if (rs.next()) {
                return Optional.of(new SessionRecord(rs.getBytes(SESSION_RECORD_COLUMN)));
            }
            return Optional.empty();
        } catch (SQLException | IOException e) {
            System.out.println(e.getMessage());
            return Optional.empty();
        }
    }

    public List<Integer> getSubDeviceSessions(String name) {
        try (Connection conn = databaseService.connect();
             PreparedStatement statement  = conn.prepareStatement(READ_SESSIONS_BY_NAME_STATEMENT)) {

            statement.setString(1, name);
            ResultSet rs  = statement.executeQuery();

            List<Integer> result = new ArrayList<>();
            while (rs.next()) {
                result.add(rs.getInt(DEVICE_ID_COLUMN));
            }
            return result;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return List.of();
        }
    }

    public void delete(SignalProtocolAddress address) {
        try (Connection conn = databaseService.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_SESSION_STATEMENT)) {

            stmt.setString(1, address.getName());
            stmt.setInt(2, address.getDeviceId());
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void deleteAll(String name) {
        try (Connection conn = databaseService.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_ALL_SESSIONS_STATEMENT)) {

            stmt.setString(1, name);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    private void init() {
        String createSessionTableCmd = "CREATE TABLE IF NOT EXISTS " + SESSION_TABLE_NAME + " (\n"
                + NAME_COLUMN + " text NOT NULL,\n"
                + DEVICE_ID_COLUMN + " integer NOT NULL,\n"
                + SESSION_RECORD_COLUMN + "	blob NOT NULL,\n"
                + "UNIQUE(" + DEVICE_ID_COLUMN + "," + NAME_COLUMN + ")\n"
                + ");";

        databaseService.createTable(createSessionTableCmd);
    }

}
