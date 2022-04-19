package io.blindnet.blindnet.domain.key;

import javax.crypto.SecretKey;
import java.util.Base64;

/**
 * A wrapper class for the symmetric key in JWK format.
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
