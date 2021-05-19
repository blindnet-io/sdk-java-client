package io.blindnet.blindnet.exception;

/**
 * Exception indicating that jwt is either expired or invalid.
 */
public class InvalidJwtException extends RuntimeException {

    public InvalidJwtException(String message) {
        super(message);
    }

}