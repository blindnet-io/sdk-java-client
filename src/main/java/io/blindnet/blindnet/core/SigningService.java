package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.SignatureException;
import org.json.JSONObject;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides API for cryptographic signing and verification of the cryptographic signature.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
class SigningService {

    private static final Logger LOGGER = Logger.getLogger(EncryptionService.class.getName());

    /**
     * Signs data using provided private key.
     *
     * @param data             a data to be signed.
     * @param privateKey       a private key used for signing.
     * @param signingAlgorithm an algorithm to be used for signing.
     * @return a base64 encoded signed data.
     */
    public String sign(String data, PrivateKey privateKey, String signingAlgorithm) {
        return sign(data.getBytes(), privateKey, signingAlgorithm);
    }

    /**
     * Signs object using provided private key.
     *
     * @param object           an object to be signed.
     * @param privateKey       a private key used for signing.
     * @param signingAlgorithm an algorithm used for signing.
     * @return a base64 encoded signed object.
     */
    public String sign(Object object, PrivateKey privateKey, String signingAlgorithm) {
        JSONObject jsonObject = new JSONObject(object);
        return sign(jsonObject.toString().getBytes(), privateKey, signingAlgorithm);
    }

    /**
     * Verifies signature.
     *
     * @param signedObject     a signed object.
     * @param base64Signature  a base 64 encoded signature value.
     * @param publicKey        a public key used for verification.
     * @param signingAlgorithm an algorithm used for signing.
     * @return indication if signature is valid.
     */
    public boolean verify(Object signedObject,
                          String base64Signature,
                          PublicKey publicKey,
                          String signingAlgorithm) {

        try {
            Signature signature = Signature.getInstance(signingAlgorithm);
            signature.initVerify(publicKey);

            JSONObject jsonObject = new JSONObject(signedObject);
            signature.update(jsonObject.toString().getBytes());
            return signature.verify(Base64.getUrlDecoder().decode(base64Signature));
        } catch (GeneralSecurityException exception) {
            String msg = "Error during signature validation. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg, exception);
            throw new SignatureException(msg, exception);
        }
    }

    /**
     * Signs data using provided private key.
     *
     * @param data             a data to be signed.
     * @param privateKey       a private key used for signing.
     * @param signingAlgorithm an algorithm used for signing.
     * @return a base64 encoded signed data.
     */
    private String sign(byte[] data, PrivateKey privateKey, String signingAlgorithm) {

        try {
            Signature signature = Signature.getInstance(signingAlgorithm);
            signature.initSign(privateKey);
            signature.update(data);
            byte[] signatureValue = signature.sign();

            return Base64.getUrlEncoder().encodeToString(signatureValue);
        } catch (GeneralSecurityException exception) {
            String msg = "Error during signature creation. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg, exception);
            throw new SignatureException(msg, exception);
        }
    }

}
