package io.blindnet.blindnet.exception;

/**
 * Exception indicating that generation of key or key pair failed due to an invalid algorithm or provider.
 */
public class KeyGenerationException extends RuntimeException {

    public KeyGenerationException(String message) {
        super(message);
    }

}
