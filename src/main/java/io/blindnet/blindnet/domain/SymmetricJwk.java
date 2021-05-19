package io.blindnet.blindnet.domain;

import javax.crypto.SecretKey;
import java.util.Base64;

/**
 * Represents symmetric key in jwk format.
 */
public final class SymmetricJwk {

    /**
     * A key type.
     */
    private final String kty;

    /**
     * A key value.
     */
    private final String k;

    public SymmetricJwk(SecretKey secretKey) {
        this.kty = "oct";
        this.k = Base64.getUrlEncoder().encodeToString(secretKey.getEncoded());
    }

    public String getKty() {
        return kty;
    }

    public String getK() {
        return k;
    }

}
