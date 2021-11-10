package io.blindnet.blindnet.internal;

import java.sql.*;

import static io.blindnet.blindnet.internal.DatabaseConfig.DATABASE_NAME;

// todo rename
public class DatabaseService {

    private static final String URL_PREFIX = "jdbc:sqlite:";

    // todo singleton, exception handling, javadoc

    public static String URL;

    public DatabaseService() {
        URL = URL_PREFIX + DatabaseConfig.INSTANCE.getDbPath() + DATABASE_NAME;
    }

    public void createTable(String command) {
        try (Connection conn = DriverManager.getConnection(URL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(command);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public Connection connect() {
        try {
            return DriverManager.getConnection(URL);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

}

