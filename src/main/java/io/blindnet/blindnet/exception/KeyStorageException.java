package io.blindnet.blindnet.exception;

/**
 * Exception indicating that a private key could not be stored due to IO problems.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class KeyStorageException extends RuntimeException {

    public KeyStorageException(String message) {
        super(message);
    }

    public KeyStorageException(String message, Throwable cause) {
        super(message, cause);
    }

}
