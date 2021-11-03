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
    public static final String SIGNAL_FETCH_USER_DEVICE_IDS = "/api/v1/signal/devices/";
    public static final String SIGNAL_FETCH_PUBLIC_KEYS_ENDPOINT_PATH = "/api/v1/signal/keys/";
    public static final String SIGNAL_UPLOAD_PUBLIC_KEYS_ENDPOINT_PATH = "/api/v1/signal/keys/me";
    public static final String SIGNAL_UPLOAD_BACKUP_ENDPOINT_PATH = "/api/v1/messages/backup";
    public static final String SIGNAL_FETCH_BACKUP_MESSAGES_ENDPOINT_PATH = "/api/v1/messages/backup";
    public static final String SIGNAL_FETCH_BACKUP_SALT_ENDPOINT_PATH = "/api/v1/messages/backup/salt";
    public static final String SIGNAL_SEND_MESSAGE_ENDPOINT_PATH = "/api/v1/messages";
    public static final String SIGNAL_FETCH_MESSAGE_IDS_ENDPOINT_PATH = "/api/v1/messages";
    public static final String SIGNAL_FETCH_MESSAGES_ENDPOINT_PATH = "/api/v1/messages/content";

}
