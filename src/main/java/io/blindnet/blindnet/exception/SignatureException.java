package io.blindnet.blindnet.exception;

/**
 * Exception indicating that a calculation or verifying of a signature failed.
 */
public class SignatureException extends RuntimeException {

    public SignatureException(String message) {
        super(message);
    }

}
