package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.SignatureException;
import org.json.JSONObject;

import java.security.*;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * todo javadoc
 * todo package view not public
 *
 * @author stefanveselinovic
 */
public class SigningService {

    private static final Logger LOGGER = Logger.getLogger(EncryptionService.class.getName());

    /**
     * Signs data using provided private key.
     *
     * @param data             data to be signed.
     * @param privateKey       Private key used for signing.
     * @param signingAlgorithm Algorithm to be used for signing.
     * @return Base64 signed JWT.
     */
    public String sign(String data, PrivateKey privateKey, String signingAlgorithm) {
        return sign(data.getBytes(), privateKey, signingAlgorithm);
    }

    /**
     * todo javadoc
     *
     * @param object
     * @param privateKey
     * @param signingAlgorithm
     * @return
     */
    public String sign(Object object, PrivateKey privateKey, String signingAlgorithm) {
        JSONObject jsonObject = new JSONObject(object);
        return sign(jsonObject.toString().getBytes(), privateKey, signingAlgorithm);
    }

    /**
     * todo javadoc
     *
     * @param signedObject
     * @param base64Signature
     * @param publicKey
     * @param signingAlgorithm
     * @return
     * @throws InvalidKeyException
     * @throws SignatureException
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
     * todo javadoc
     *
     * @param data
     * @param privateKey
     * @param signingAlgorithm
     * @return
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
