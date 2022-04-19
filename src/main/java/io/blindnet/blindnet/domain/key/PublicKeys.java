package io.blindnet.blindnet.domain.key;

import java.security.PublicKey;

/**
 * A wrapper class for the encryption and signing public keys.
 */
public final class PublicKeys {

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

    public PublicKeys(PublicKey encryptionKey,
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
