package io.blindnet.blindnet.exception;

/**
 * todo javadoc
 *
 * @author stefanveselinovic
 */
public class EncryptionException extends RuntimeException {

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

}
