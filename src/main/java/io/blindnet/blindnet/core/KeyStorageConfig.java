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
     * Represents a folder path where a public signing key of recipients witll be stored.
     */
    private String recipientSigningPublicKeyFolderPath;

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
    public void setup(String encryptionPrivateKeyPath,
                      String signingPrivateKeyPath,
                      String recipientSigningPublicKeyFolderPath) {

        requireNonNull(encryptionPrivateKeyPath, "Encryption key filepath cannot be null.");
        requireNonNull(signingPrivateKeyPath, "Signing key filepath cannot be null.");
        requireNonNull(recipientSigningPublicKeyFolderPath, "Recipient signing key folder path cannot be null.");

        this.encryptionPrivateKeyPath = encryptionPrivateKeyPath;
        this.signingPrivateKeyPath = signingPrivateKeyPath;
        this.recipientSigningPublicKeyFolderPath = recipientSigningPublicKeyFolderPath;
    }

    /**
     * Returns a file path where a private key used for encryption will be stored.
     *
     * @return a file path.
     */
    public String getEncryptionPrivateKeyPath() {
        return encryptionPrivateKeyPath;
    }

    /**
     * Returns a file path where a private key used for signing will be stored.
     *
     * @return a file path.
     */
    public String getSigningPrivateKeyPath() {
        return signingPrivateKeyPath;
    }

    /**
     * Returns a folder path where public signing keys of recipients will be stored.
     *
     * @return a folder path.
     */
    public String getRecipientSigningPublicKeyFolderPath() {
        return recipientSigningPublicKeyFolderPath;
    }

}
