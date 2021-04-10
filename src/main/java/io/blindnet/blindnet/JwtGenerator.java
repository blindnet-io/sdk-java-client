package io.blindnet.blindnet;

import java.util.Base64;

/**
 * Temporary jwt generator.
 *
 * to be removed
 */
public class JwtGenerator {

    private static final String JWT_HEADER = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";

    public static String generateJwt() {
        Base64.Encoder encoder = Base64.getUrlEncoder();
        String payload = "{ \"app\":\"1234\",\"uid\":\"4567\",\"exp\":1617740103}";

        String encodedPayload = encoder.encodeToString(payload.getBytes());
        String encodedHeader = encoder.encodeToString(JWT_HEADER.getBytes());

        return encodedHeader + "." + encodedPayload;
    }
}
