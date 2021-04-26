package io.blindnet.blindnet.domain;

import java.security.PublicKey;

//todo javadoc
public class PublicKeyPair {

    private final PublicKey encryptionKey;
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
