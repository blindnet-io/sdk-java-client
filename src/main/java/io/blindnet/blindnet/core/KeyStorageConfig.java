package io.blindnet.blindnet.core;

import static java.util.Objects.requireNonNull;

/**
 * Provides Singleton instance for the key storage configuration.
 */
enum KeyStorageConfig {

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

        requireNonNull(keyFolderPath, "Key folder path cannot be null.");

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
