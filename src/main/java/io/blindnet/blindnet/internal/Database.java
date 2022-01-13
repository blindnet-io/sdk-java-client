package io.blindnet.blindnet.internal;

import io.blindnet.blindnet.exception.StorageException;

import java.sql.*;

import static io.blindnet.blindnet.internal.DatabaseConfig.DATABASE_NAME;

/**
 * Provides API for database connection and sql command execution.
 */
public class Database {

    /**
     * The URL prefix used to connect to SQLite database.
     */
    private static final String URL_PREFIX = "jdbc:sqlite:";

    /**
     * Database connection URL.
     */
    public static String URL;

    /**
     * Private constructor as class implements Singleton pattern.
     */
    private Database() {
        URL = URL_PREFIX + DatabaseConfig.INSTANCE.getDbPath() + DATABASE_NAME;
    }

    /**
     * Inner class which holds Singleton instance.
     */
    private static class InstanceHolder {
        public static final Database instance = new Database();
    }

    /**
     * Returns Singleton instance of the class.
     *
     * @return DatabaseService object.
     */
    public static Database getInstance() {
        return Database.InstanceHolder.instance;
    }

    /**
     * Creates a connection to the database.
     *
     * @return a Connection object.
     */
    public Connection connect() {
        try {
            return DriverManager.getConnection(URL);
        } catch (SQLException e) {
            throw new StorageException("Unable to connect to the SQLite database with URL: " + URL);
        }
    }

    /**
     * Executes statement in the SQLite database.
     *
     * @param command statement command.
     */
    public void executeStatement(String command) {
        try (Connection conn = DriverManager.getConnection(URL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(command);
        } catch (SQLException e) {
            throw new StorageException("Unable to create SQLite table");
        }
    }

}

