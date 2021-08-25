package io.blindnet.blindnet.exception;

/**
 * Exception indicating that un-registration of a user failed.
 */
public class UnregisterException extends RuntimeException {

    public UnregisterException(String message) {
        super(message);
    }

}
