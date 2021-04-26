package io.blindnet.blindnet.exception;

/**
 * todo javadoc
 *
 * @author stefanveselinovic
 */
public class KeyEncryptionException extends RuntimeException {

    public KeyEncryptionException(String message) {
        super(message);
    }

    public KeyEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

}
