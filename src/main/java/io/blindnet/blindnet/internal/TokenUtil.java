package io.blindnet.blindnet.internal;

import org.json.JSONObject;

import java.util.Base64;

/**
 * Provides API for Token related operations.
 */
public class TokenUtil {

    private static final String USER_ID_FIELD = "uid";

    private TokenUtil() {
    }

    /**
     * Extracts user's ID from Token.
     *
     * @param token a token object of a user.
     * @return User's ID.
     */
    public static String extractUserId(String token) {
        String[] data = token.split("\\.");
        JSONObject payload = new JSONObject(new String(Base64.getUrlDecoder().decode(data[1])));
        return payload.getString(USER_ID_FIELD);
    }

}
