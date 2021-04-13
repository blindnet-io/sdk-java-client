package io.blindnet.blindnet.exception;

/**
 * Exception indicating that jwt signing failed because signature could not be calculated or invalid key was used.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class JwtException extends RuntimeException {

    public JwtException(String message) {
        super(message);
    }

    public JwtException(String message, Throwable cause) {
        super(message, cause);
    }

}
