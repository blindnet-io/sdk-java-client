package io.blindnet.blindnet.internal;

/**
 * Provides url endpoints of Blindnet api.
 */
public class ApiClientConstants {

    private ApiClientConstants() {
    }

    public static final String USER_ENDPOINT_PATH = "/api/v1/users";
    public static final String DELETE_USER_ENDPOINT_PATH = "/api/v1/users/me";
    public static final String SYMMETRIC_KEY_ENDPOINT_PATH = "/api/v1/messages/keys";
    public static final String PRIVATE_KEYS_ENDPOINT_PATH = "/api/v1/keys/me";
    public static final String FETCH_PUBLIC_KEYS_ENDPOINT_PATH = "/api/v1/keys/";

    public static final String SIGNAL_USER_ENDPOINT_PATH = "/api/v1/signal/users";
    public static final String SIGNAL_DELETE_USER_ENDPOINT_PATH = "/api/v1/users/me";
    public static final String SIGNAL_FETCH_PUBLIC_KEYS_ENDPOINT_PATH = "/api/v1/signal/keys/";

}
