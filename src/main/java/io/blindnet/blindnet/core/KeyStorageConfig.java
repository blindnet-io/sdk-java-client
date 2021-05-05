package io.blindnet.blindnet.core;

import static java.util.Objects.requireNonNull;

/**
 * Provides Singleton instance for the key storage configuration.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public enum KeyStorageConfig {

    /**
     * Key Storage Config Instance.
     */
    INSTANCE;

    /**
     * Represents a file path where a private key used for encryption will be stored.
     */
    private String encryptionPrivateKeyPath;

    /**
     * Represents a file path where a private key used for signing will be stored.
     */
    private String signingPrivateKeyPath;

    /**
     * A constructor, which is private by default.
     */
    KeyStorageConfig() { }

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
     * @param encryptionPrivateKeyPath A file path where a private key used for encryption will be stored.
     * @param signingPrivateKeyPath A file path where a private key used for signing will be stored.
     */
    public void setup(String encryptionPrivateKeyPath, String signingPrivateKeyPath) {
        requireNonNull(encryptionPrivateKeyPath, "Encryption key filepath cannot be null.");
        requireNonNull(signingPrivateKeyPath, "Signing key filepath cannot be null.");

        this.encryptionPrivateKeyPath = encryptionPrivateKeyPath;
        this.signingPrivateKeyPath = signingPrivateKeyPath;
    }

    /**
     * Returns a file path where a private key used for encryption will be stored.
     *
     * @return A file path as a String.
     */
    public String getEncryptionPrivateKeyPath() {
        return encryptionPrivateKeyPath;
    }

    /**
     * Returns a file path where a private key used for signing will be stored.
     *
     * @return A file path as a String.
     */
    public String getSigningPrivateKeyPath() {
        return signingPrivateKeyPath;
    }

}
