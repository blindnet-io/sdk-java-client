package io.blindnet.blindnet.exception;

/**
 * Exception indicating that a private key could not be stored due to IO error.
 */
public class KeyStorageException extends RuntimeException {

    public KeyStorageException(String message) {
        super(message);
    }

}
