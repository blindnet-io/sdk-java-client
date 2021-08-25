package io.blindnet.blindnet.internal;

import java.io.File;

public enum DatabaseConfig {

    /**
     * Database Config Instance.
     */
    INSTANCE;

    public static final String DATABASE_NAME = "blindnet.db";

    /**
     * Represents a folder path where database is stored.
     */
    private String dbPath;

    /**
     * A constructor, which is private by default.
     */
    DatabaseConfig() {
    }

    /**
     * Returns Singleton Instance for Database Config.
     *
     * @return DatabaseConfig Singleton
     */
    public DatabaseConfig getInstance() {
        return INSTANCE;
    }

    /**
     * Setup for Database configuration.
     *
     * @param dbPath a path to the folder where database is stored.
     */
    public void setup(String dbPath) {

        if (!dbPath.endsWith(File.separator)) {
            dbPath = dbPath + File.separator;
        }
        this.dbPath = dbPath;
    }

    /**
     * Returns a folder path where database is stored.
     *
     * @return a folder path.
     */
    public String getDbPath() {
        return dbPath;
    }

}
