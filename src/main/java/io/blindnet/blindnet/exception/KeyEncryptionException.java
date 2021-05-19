package io.blindnet.blindnet.exception;

/**
 * Exception indicating that encryption of the key failed.
 */
public class KeyEncryptionException extends RuntimeException {

    public KeyEncryptionException(String message) {
        super(message);
    }

}
