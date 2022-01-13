package io.blindnet.blindnet.exception;

/**
 * Exception indicating storing of data has failed.
 */
public class StorageException extends RuntimeException {

    public StorageException(String message) {
        super(message);
    }

}
