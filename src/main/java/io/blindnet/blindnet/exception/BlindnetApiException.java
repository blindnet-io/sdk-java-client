package io.blindnet.blindnet.exception;

/**
 * Exception indicating that Blindnet API did not return HTTP 200 Ok response.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class BlindnetApiException extends RuntimeException {

    public BlindnetApiException(String message) {
        super(message);
    }

    public BlindnetApiException(String message, Throwable cause) {
        super(message, cause);
    }

}
