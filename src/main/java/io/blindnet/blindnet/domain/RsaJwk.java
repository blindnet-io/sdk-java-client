package io.blindnet.blindnet.domain;

import io.blindnet.blindnet.exception.KeyConstructionException;

import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Represents RSA private key in jwk format.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public final class RsaJwk {

    private static final Logger LOGGER = Logger.getLogger(RsaJwk.class.getName());

    /**
     * A key pair type.
     */
    private final String kty;

    /**
     * The modulus value for the RSA key.
     */
    private final String n;

    /**
     * The public exponent of the RSA key.
     */
    private final String e;

    /**
     * The private exponent of the RSA key.
     */
    private final String d;

    /**
     * The first private factor of the private RSA key.
     */
    private final String p;

    /**
     * The second prime factor of the private RSA key.
     */
    private final String q;

    /**
     * The first factor Chinese Remainder Theorem exponent of the
     * private RSA key.
     */
    private final String dp;

    /**
     * The second factor Chinese Remainder Theorem exponent of the
     * private RSA key.
     */
    private final String dq;

    /**
     * The first Chinese Remainder Theorem coefficient of the private RSA
     * key.
     */
    private final String qi;

    public RsaJwk(PrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateCrtKey)) {
            String msg = "Error while converting private key to jwk format.";
            LOGGER.log(Level.SEVERE, msg);
            throw new KeyConstructionException(msg);
        }
        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
        Base64.Encoder encoder = Base64.getUrlEncoder();

        this.kty = "RSA";
        this.n = encoder.encodeToString(rsaPrivateCrtKey.getModulus().toByteArray());
        this.e = encoder.encodeToString(rsaPrivateCrtKey.getPublicExponent().toByteArray());
        this.d = encoder.encodeToString(rsaPrivateCrtKey.getPrivateExponent().toByteArray());
        this.p = encoder.encodeToString(rsaPrivateCrtKey.getPrimeP().toByteArray());
        this.q = encoder.encodeToString(rsaPrivateCrtKey.getPrimeQ().toByteArray());
        this.dp = encoder.encodeToString(rsaPrivateCrtKey.getPrimeExponentP().toByteArray());
        this.dq = encoder.encodeToString(rsaPrivateCrtKey.getPrimeExponentQ().toByteArray());
        this.qi = encoder.encodeToString(rsaPrivateCrtKey.getCrtCoefficient().toByteArray());
    }

    public String getKty() {
        return kty;
    }

    public String getN() {
        return n;
    }

    public String getE() {
        return e;
    }

    public String getD() {
        return d;
    }

    public String getP() {
        return p;
    }

    public String getQ() {
        return q;
    }

    public String getDp() {
        return dp;
    }

    public String getDq() {
        return dq;
    }

    public String getQi() {
        return qi;
    }

}
