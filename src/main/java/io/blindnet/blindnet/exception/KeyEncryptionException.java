package io.blindnet.blindnet.exception;

/**
 * Exception indicating that encryption of the key failed.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class KeyEncryptionException extends RuntimeException {

    public KeyEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

}
