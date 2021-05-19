package io.blindnet.blindnet.exception;

/**
 * Exception indicating that key construction failed.
 */
public class KeyConstructionException extends RuntimeException {

    public KeyConstructionException(String message) {
        super(message);
    }

    public KeyConstructionException(String message, Throwable cause) {
        super(message, cause);
    }

}
