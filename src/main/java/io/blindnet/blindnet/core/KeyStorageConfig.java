package io.blindnet.blindnet.core;

import java.util.Objects;

/**
 * Provides Singleton instance for key storage configuration.
 *
 * @author stefanveselinovic
 */
public enum KeyStorageConfig {

    //todo add java doc

    INSTANCE;

    private String encryptionPrivateKeyPath;
    private String signingPrivateKeyPath;

    KeyStorageConfig() { }

    public KeyStorageConfig getInstance() {
        return INSTANCE;
    }

    public void init(String encryptionPrivateKeyPath, String signingPrivateKeyPath) {
        Objects.requireNonNull(encryptionPrivateKeyPath, "null encryption private key path");
        Objects.requireNonNull(signingPrivateKeyPath, "null signing private key path");
        this.encryptionPrivateKeyPath = encryptionPrivateKeyPath;
        this.signingPrivateKeyPath = signingPrivateKeyPath;
    }

    public String getEncryptionPrivateKeyPath() {
        return encryptionPrivateKeyPath;
    }

    public String getSigningPrivateKeyPath() {
        return signingPrivateKeyPath;
    }

}
