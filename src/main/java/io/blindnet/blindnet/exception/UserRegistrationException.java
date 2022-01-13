package io.blindnet.blindnet.exception;

/**
 * Exception indicating that un-registration of a user failed.
 */
public class UserRegistrationException extends RuntimeException {

    public UserRegistrationException(String message) {
        super(message);
    }

}
