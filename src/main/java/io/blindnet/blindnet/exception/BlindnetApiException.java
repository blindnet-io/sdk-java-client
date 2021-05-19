package io.blindnet.blindnet.exception;

/**
 * Exception indicating that Blindnet API did not return HTTP 200 Ok response.
 */
public class BlindnetApiException extends RuntimeException {

    public BlindnetApiException(String message) {
        super(message);
    }

}
