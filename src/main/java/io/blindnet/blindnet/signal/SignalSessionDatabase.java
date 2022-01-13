package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.exception.StorageException;
import io.blindnet.blindnet.internal.Database;
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

/**
 * Database API used for storing of Signal sessions.
 */
class SignalSessionDatabase {

    private static final String SESSION_TABLE_NAME = "session";
    private static final String NAME_COLUMN = "name";
    private static final String DEVICE_ID_COLUMN = "device_id";
    private static final String SESSION_RECORD_COLUMN = "session_record";

    private static final String INSERT_SESSION_STATEMENT = "INSERT INTO session (name, device_id, session_record) VALUES(?, ?, ?)";
    private static final String UPDATE_SESSION_STATEMENT = "UPDATE session SET session_record = ? WHERE name = ? and device_id = ?";
    private static final String READ_SESSION_STATEMENT = "SELECT session_record FROM session WHERE name = ? AND device_id = ?";
    private static final String READ_SESSIONS_BY_NAME_STATEMENT = "SELECT device_id FROM session WHERE name = ? AND device_id != 1";
    private static final String DELETE_SESSION_STATEMENT = "DELETE FROM session WHERE name = ? AND device_id = ?";
    private static final String DELETE_ALL_SESSIONS_STATEMENT = "DELETE FROM session WHERE name = ?";

    private final Database database;

    public SignalSessionDatabase() {
        database = Database.getInstance();
        init();
    }

    /**
     * Stores Signal session.
     *
     * @param address a signal address.
     * @param record  a session record.
     */
    public void store(SignalProtocolAddress address, SessionRecord record) {
        try (Connection conn = database.connect();
             PreparedStatement statement = conn.prepareStatement(INSERT_SESSION_STATEMENT)) {

            statement.setString(1, address.getName());
            statement.setInt(2, address.getDeviceId());
            statement.setBytes(3, record.serialize());
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to store signal session.");
        }
    }

    /**
     * Updates signal session.
     *
     * @param address a signal address.
     * @param record  a session record.
     */
    public void updateSession(SignalProtocolAddress address, SessionRecord record) {
        try (Connection conn = database.connect();
             PreparedStatement statement = conn.prepareStatement(UPDATE_SESSION_STATEMENT)) {

            statement.setBytes(1, record.serialize());
            statement.setString(2, address.getName());
            statement.setInt(3, address.getDeviceId());

            statement.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to update signal session");
        }
    }

    /**
     * Loads Signal session based on address.
     *
     * @param address a signal address.
     * @return an optional wrapper of signal session record.
     */
    public Optional<SessionRecord> load(SignalProtocolAddress address) {
        try (Connection conn = database.connect();
             PreparedStatement statement = conn.prepareStatement(READ_SESSION_STATEMENT)) {

            statement.setString(1, address.getName());
            statement.setInt(2, address.getDeviceId());
            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                return Optional.of(new SessionRecord(rs.getBytes(SESSION_RECORD_COLUMN)));
            }
            return Optional.empty();
        } catch (SQLException | IOException e) {
            throw new StorageException("Unable to load signal session");
        }
    }

    /**
     * Loads all device ids of a signal session.
     *
     * @param name a name of the session address.
     * @return a list of device ids.
     */
    public List<Integer> getSubDeviceSessions(String name) {
        try (Connection conn = database.connect();
             PreparedStatement statement = conn.prepareStatement(READ_SESSIONS_BY_NAME_STATEMENT)) {

            statement.setString(1, name);
            ResultSet rs = statement.executeQuery();

            List<Integer> result = new ArrayList<>();
            while (rs.next()) {
                result.add(rs.getInt(DEVICE_ID_COLUMN));
            }
            return result;
        } catch (SQLException e) {
            throw new StorageException("Unable to load device ids of signal session.");
        }
    }

    /**
     * Deletes signal session based on address.
     *
     * @param address a signal address.
     */
    public void delete(SignalProtocolAddress address) {
        try (Connection conn = database.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_SESSION_STATEMENT)) {

            stmt.setString(1, address.getName());
            stmt.setInt(2, address.getDeviceId());
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to delete signal session.");
        }
    }

    /**
     * Deletes all signal sessions based on provided name.
     *
     * @param name a signal address name.
     */
    public void deleteAll(String name) {
        try (Connection conn = database.connect();
             PreparedStatement stmt = conn.prepareStatement(DELETE_ALL_SESSIONS_STATEMENT)) {

            stmt.setString(1, name);
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("Unable to delete signal sessions.");
        }
    }

    /**
     * Initialization method that creates session table.
     */
    private void init() {
        String createSessionTableCmd = "CREATE TABLE IF NOT EXISTS " + SESSION_TABLE_NAME + " (\n"
                + NAME_COLUMN + " text NOT NULL,\n"
                + DEVICE_ID_COLUMN + " integer NOT NULL,\n"
                + SESSION_RECORD_COLUMN + "	blob NOT NULL\n"
                //+ "UNIQUE(" + DEVICE_ID_COLUMN + "," + NAME_COLUMN + ")\n"
                + ");";

        database.executeStatement(createSessionTableCmd);
    }

}
