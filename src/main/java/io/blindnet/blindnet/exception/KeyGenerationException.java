package io.blindnet.blindnet.exception;

/**
 * Exception indicating that generation of key or key pair failed due to an invalid algorithm or provider.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class KeyGenerationException extends RuntimeException {

    public KeyGenerationException(String message) {
        super(message);
    }

    public KeyGenerationException(String message, Throwable cause) {
        super(message, cause);
    }

}
