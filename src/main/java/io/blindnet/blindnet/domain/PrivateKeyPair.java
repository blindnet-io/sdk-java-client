package io.blindnet.blindnet.domain;

/**
 * A wrapper object for the encryption and signing private keys.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public final class PrivateKeyPair {

    /**
     * A private key used for encryption.
     */
    private final String encryptionKey;

    /**
     * A private key used for signing.
     */
    private final String signingKey;

    /**
     * A key derivation salt used to create secret encryption key.
     */
    private final String keyDerivationSalt;

    public PrivateKeyPair(String encryptionKey, String signingKey, String keyDerivationSalt) {
        this.encryptionKey = encryptionKey;
        this.signingKey = signingKey;
        this.keyDerivationSalt = keyDerivationSalt;
    }

    public String getEncryptionKey() {
        return encryptionKey;
    }

    public String getSigningKey() {
        return signingKey;
    }

    public String getKeyDerivationSalt() {
        return keyDerivationSalt;
    }

}
