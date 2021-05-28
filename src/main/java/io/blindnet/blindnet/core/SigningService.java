package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.SignatureException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Provides API for cryptographic signing and verification of the cryptographic signature.
 */
class SigningService {

    /**
     * Signs data using provided private key.
     *
     * @param data             a data to be signed.
     * @param privateKey       a private key used for signing.
     * @param signingAlgorithm an algorithm to be used for signing.
     * @return a base64 encoded signed data.
     */
    public byte[] sign(String data, PrivateKey privateKey, String signingAlgorithm) {
        return sign(data.getBytes(), privateKey, signingAlgorithm);
    }

    /**
     * Signs data using provided private key.
     *
     * @param data             a data to be signed.
     * @param privateKey       a private key used for signing.
     * @param signingAlgorithm an algorithm used for signing.
     * @return a base64 encoded signature.
     */
    public byte[] sign(byte[] data, PrivateKey privateKey, String signingAlgorithm) {

        try {
            Signature signature = Signature.getInstance(signingAlgorithm);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new SignatureException("Error during signature creation.");
        }
    }

    /**
     * Verifies signature.
     *
     * @param signedData       a signed data.
     * @param base64Signature  a base 64 encoded signature value.
     * @param publicKey        a public key used for verification.
     * @param signingAlgorithm an algorithm used for signing.
     * @return indication if signature is valid.
     */
    public boolean verify(byte[] signedData,
                          String base64Signature,
                          PublicKey publicKey,
                          String signingAlgorithm) {

        try {
            Signature signature = Signature.getInstance(signingAlgorithm);
            signature.initVerify(publicKey);
            signature.update(signedData);
            return signature.verify(Base64.getDecoder().decode(base64Signature));
        } catch (GeneralSecurityException exception) {
            throw new SignatureException("Error during signature validation.");
        }
    }

}
