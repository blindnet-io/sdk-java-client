package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.JwtException;

import java.security.*;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides API to sign jwt and verify it's signature.
 *
 * @author stefanveselinovic
 */
class JwtService {

    private static final Logger LOGGER = Logger.getLogger(JwtService.class.getName());

    // todo FR-SDK06
    public boolean verify(String signature, PublicKey publicKey) {
        // todo verify signature with public key
        System.out.println("Verifies signature with public key..");
        return true;
    }

    /**
     * Signs JWT using provided private key.
     *
     * @param jwt JWT object to be signed.
     * @param privateKey Private key used for signing.
     * @param signingAlgorithm Algorithm to be used for signing.
     * @return Base64 signed JWT.
     */
    public String sign(String jwt, PrivateKey privateKey, String signingAlgorithm) {
        try {
            return doSign(jwt, privateKey, signingAlgorithm);
        } catch (InvalidKeyException exception) {
            throw new JwtException("Invalid signing Private Key. " + exception.getMessage(), exception);
        } catch (SignatureException exception) {
            throw new JwtException("Unable to calculate Signature value. " + exception.getMessage(), exception);
        }
    }

    /**
     * Signs JWT using provided private key.
     *
     * @param jwt JWT object to be signed.
     * @param privateKey Private key used for signing.
     * @param signingAlgorithm Algorithm to be used for signing.
     * @return Base64 signed JWT.
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private String doSign(String jwt, PrivateKey privateKey, String signingAlgorithm) throws InvalidKeyException,
            SignatureException {

        Signature signature = createSignature(signingAlgorithm);
        signature.initSign(privateKey);
        signature.update(jwt.getBytes());
        byte[] signatureValue = signature.sign();

        return Base64.getUrlEncoder().encodeToString(signatureValue);
    }

    /**
     * Creates Signature instance based on provided algorithm.
     *
     * @param signingAlgorithm Signing algorithm used to create signature.
     * @return Signature object.
     */
    private Signature createSignature(String signingAlgorithm) {
        try {
            return Signature.getInstance(signingAlgorithm);
        } catch (NoSuchAlgorithmException exception) {
            String msg = "Unable to create a signature instance. Invalid signature algorithm." + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg, exception);
            throw new JwtException(msg, exception);
        }
    }

}
