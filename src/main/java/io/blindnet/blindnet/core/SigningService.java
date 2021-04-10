package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.JwtException;

import java.security.*;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.blindnet.blindnet.domain.EncryptionConstants.JWT_CONTENT_SEPARATOR;

//todo change class name
class SigningService {

    private static final Logger LOGGER = Logger.getLogger(SigningService.class.getName());

    public String sign(String jwt, PrivateKey privateKey, String signingAlgorithm) {
        try {
            return doSign(jwt, privateKey, signingAlgorithm);
        } catch (InvalidKeyException exception) {
            throw new JwtException("Invalid signing Private Key. " + exception.getMessage(), exception);
        } catch (SignatureException exception) {
            throw new JwtException("Unable to calculate Signature value. " + exception.getMessage(), exception);
        }
    }

    // todo FR-SDK06
    public static boolean verify(String signature, PublicKey publicKey) {
        // todo verify signature with public key
        System.out.println("Verifies signature with public key..");
        return true;
    }

    private String doSign(String jwt, PrivateKey privateKey, String signingAlgorithm) throws InvalidKeyException,
            SignatureException {

        Signature signature = createSignature(signingAlgorithm);
        signature.initSign(privateKey);
        signature.update(jwt.getBytes());
        byte[] signatureValue = signature.sign();

        return jwt + JWT_CONTENT_SEPARATOR + Base64.getUrlEncoder().encodeToString(signatureValue);
    }

    private Signature createSignature(String signingAlgorithm) {
        try {
            return Signature.getInstance(signingAlgorithm);
        } catch (NoSuchAlgorithmException exception) {
            String msg = "Unavailable  to create signature instance. Invalid signature algorithm.";
            LOGGER.log(Level.SEVERE, msg, exception);
            throw new JwtException(msg, exception);
        }
    }

}
