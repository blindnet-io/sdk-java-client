package io.blindnet.blindnet.core;

import org.json.JSONObject;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * Provides API to sign jwt and verify it's signature.
 *
 * @author stefanveselinovic
 */
class JwtService {

    private static final String USED_ID = "uid";

    private SigningService signingService;

    public JwtService() {
        // todo to be changed
        signingService = new SigningService();
    }

    /**
     * Signs JWT using provided private key.
     *
     * @param jwt              JWT object to be signed.
     * @param privateKey       Private key used for signing.
     * @param signingAlgorithm Algorithm to be used for signing.
     * @return Base64 signed JWT.
     */
    // todo check if needed
    public String sign(String jwt, PrivateKey privateKey, String signingAlgorithm) {
        return signingService.sign(jwt, privateKey, signingAlgorithm);
    }

    /**
     * Extracts user's ID from Jwt.
     *
     * @param jwt a JWT object of a user.
     * @return User's ID.
     */
    public String extractUserId(String jwt) {
        String[] data = jwt.split("\\.");
        JSONObject payload = new JSONObject(new String(Base64.getUrlDecoder().decode(data[1])));
        return String.valueOf(payload.getInt(USED_ID));
    }

}
