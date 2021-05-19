package io.blindnet.blindnet.core;

/**
 * Provides url endpoints of Blindnet api.
 */
class ApiClientConstants {

    private ApiClientConstants() {
    }

    public static final String USER_ENDPOINT_PATH = "/api/v1/users";
    public static final String DELETE_USER_ENDPOINT_PATH = "/api/v1/users/me";
    public static final String SYMMETRIC_KEY_ENDPOINT_PATH = "/api/v1/messages/keys";
    public static final String PRIVATE_KEYS_ENDPOINT_PATH = "/api/v1/keys/me";
    public static final String FETCH_PUBLIC_KEYS_ENDPOINT_PATH = "/api/v1/keys/";

}