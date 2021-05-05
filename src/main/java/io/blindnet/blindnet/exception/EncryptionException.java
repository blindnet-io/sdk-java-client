package io.blindnet.blindnet.exception;

/**
 * Exception indicating that encryption failed.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class EncryptionException extends RuntimeException {

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

}
