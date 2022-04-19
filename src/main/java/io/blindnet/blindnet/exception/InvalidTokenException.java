package io.blindnet.blindnet.exception;

/**
 * Exception indicating that Token is either expired or invalid.
 */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }

}
