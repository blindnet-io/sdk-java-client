package io.blindnet.blindnet.exception;

/**
 * Exception indicating that encryption failed.
 */
public class EncryptionException extends RuntimeException {

    public EncryptionException(String message) {
        super(message);
    }

}
