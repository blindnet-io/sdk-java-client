package io.blindnet.blindnet.domain;

import java.security.PublicKey;

/**
 * A wrapper object for the encryption and signing public keys.
 * @since 0.0.1
 */
public final class PublicKeyPair {

    /**
     * A public key used for encryption.
     */
    private final PublicKey encryptionKey;

    /**
     * A public key used for signing.
     */
    private final PublicKey signingKey;

    public PublicKeyPair(PublicKey encryptionKey, PublicKey signingKey) {
        this.encryptionKey = encryptionKey;
        this.signingKey = signingKey;
    }

    public PublicKey getEncryptionKey() {
        return encryptionKey;
    }

    public PublicKey getSigningKey() {
        return signingKey;
    }

}
