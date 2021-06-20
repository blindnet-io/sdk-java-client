package io.blindnet.blindnet.internal;

import java.io.File;

/**
 * Provides Singleton instance for the key storage configuration.
 */
public enum KeyStorageConfig {

    /**
     * Key Storage Config Instance.
     */
    INSTANCE;

    /**
     * Represents a folder path where a keys will be stored.
     */
    private String keyFolderPath;

    /**
     * A constructor, which is private by default.
     */
    KeyStorageConfig() {
    }

    /**
     * Returns Singleton Instance for Key Storage Config.
     *
     * @return KeyStorageConfig Singleton
     */
    public KeyStorageConfig getInstance() {
        return INSTANCE;
    }

    /**
     * Setup for Key Storage configuration.
     *
     * @param keyFolderPath a path to the folder where keys will be stored.
     */
    public void setup(String keyFolderPath) {

        if (!keyFolderPath.endsWith(File.separator)) {
            keyFolderPath = keyFolderPath + File.separator;
        }
        this.keyFolderPath = keyFolderPath;
    }

    /**
     * Returns a folder path where keys are stored.
     *
     * @return a folder path.
     */
    public String getKeyFolderPath() {
        return keyFolderPath;
    }

}
