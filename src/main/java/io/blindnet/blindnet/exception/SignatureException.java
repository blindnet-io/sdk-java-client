package io.blindnet.blindnet.exception;

/**
 * Exception indicating that a calculation or verifying of a signature failed.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class SignatureException extends RuntimeException {

    public SignatureException(String message) {
        super(message);
    }

    public SignatureException(String message, Throwable cause) {
        super(message, cause);
    }

}
