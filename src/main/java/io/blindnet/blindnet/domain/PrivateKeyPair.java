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

    public PrivateKeyPair(String encryptionKey, String signingKey) {
        this.encryptionKey = encryptionKey;
        this.signingKey = signingKey;
    }

    public String getEncryptionKey() {
        return encryptionKey;
    }

    public String getSigningKey() {
        return signingKey;
    }

}
