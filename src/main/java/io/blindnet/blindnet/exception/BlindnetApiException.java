package io.blindnet.blindnet.exception;

/**
 *
 * @author stefanveselinovic
 */
public class BlindnetApiException extends RuntimeException {

    public BlindnetApiException(String message) {
        super(message);
    }

    public BlindnetApiException(String message, Throwable cause) {
        super(message, cause);
    }

}
