package io.blindnet.blindnet.internal;

import org.json.JSONObject;

import java.util.Base64;

/**
 * Provides API for JWT related operations.
 */
public class JwtUtil {

    private static final String USER_ID_FIELD = "uid";

    private JwtUtil() {
    }

    /**
     * Extracts user's ID from Jwt.
     *
     * @param jwt a JWT object of a user.
     * @return User's ID.
     */
    public static String extractUserId(String jwt) {
        String[] data = jwt.split("\\.");
        JSONObject payload = new JSONObject(new String(Base64.getUrlDecoder().decode(data[1])));
        return payload.getString(USER_ID_FIELD);
    }

}
