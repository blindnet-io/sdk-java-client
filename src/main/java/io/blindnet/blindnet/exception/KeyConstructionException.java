package io.blindnet.blindnet.exception;

/**
 * todo javadoc
 *
 * @author stefanveselinovic
 */
public class KeyConstructionException extends RuntimeException {

    public KeyConstructionException(String message) {
        super(message);
    }

    public KeyConstructionException(String message, Throwable cause) {
        super(message, cause);
    }

}
