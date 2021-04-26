package io.blindnet.blindnet.core;

import io.blindnet.blindnet.exception.JwtException;
import org.json.JSONObject;

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
    private static final String USED_ID = "uid";

    private EncryptionService encryptionService;

    public JwtService() {
        encryptionService = new EncryptionService();
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
            return encryptionService.sign(jwt, privateKey, signingAlgorithm);
        } catch (InvalidKeyException exception) {
            String msg = "Invalid signing Private Key. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new JwtException(msg, exception);
        } catch (SignatureException exception) {
            String msg = "Unable to calculate Signature value. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new JwtException(msg, exception);
        }
    }

    // todo FR-SDK06
    public boolean verify(String signature, PublicKey publicKey) {
        // todo verify signature with public key
        System.out.println("Verifies signature with public key..");
        return true;
    }

    public String extractUserId(String jwt) {
        String[] data = jwt.split("\\.");
        JSONObject payload = new JSONObject(new String(Base64.getUrlDecoder().decode(data[1])));
        return String.valueOf(payload.getInt(USED_ID));
    }

}
