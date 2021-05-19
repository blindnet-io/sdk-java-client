package io.blindnet.blindnet.domain;

import java.security.PublicKey;

/**
 * A wrapper object for the encryption and signing public keys.
 *
 * @author stefanveselinovic
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

    /**
     * A public encryption key signature.
     */
    private final String signedPublicEncryptionKey;

    public PublicKeyPair(PublicKey encryptionKey,
                         PublicKey signingKey,
                         String signedPublicEncryptionKey) {

        this.encryptionKey = encryptionKey;
        this.signingKey = signingKey;
        this.signedPublicEncryptionKey = signedPublicEncryptionKey;
    }

    public PublicKey getEncryptionKey() {
        return encryptionKey;
    }

    public PublicKey getSigningKey() {
        return signingKey;
    }

    public String getSignedPublicEncryptionKey() {
        return signedPublicEncryptionKey;
    }

}
