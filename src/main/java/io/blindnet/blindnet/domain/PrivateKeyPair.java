package io.blindnet.blindnet.domain;

import java.security.PrivateKey;

/**
 * todo javadoc
 *
 * @author stefanveselinovic
 */
public class PrivateKeyPair {

    private final String encryptionKey;
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
