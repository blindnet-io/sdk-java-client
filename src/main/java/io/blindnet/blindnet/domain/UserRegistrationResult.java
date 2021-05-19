package io.blindnet.blindnet.domain;

/**
 * Returns result of a registration of a user process.
 */
public final class UserRegistrationResult {

    /**
     * Indicates whether the user registration is successful.
     */
    private final boolean isSuccessful;

    /**
     * A message representing the response message of Blindnet API.
     */
    private final String message;

    public UserRegistrationResult(boolean isSuccessful, String message) {
        this.isSuccessful = isSuccessful;
        this.message = message;
    }

    public boolean isSuccessful() {
        return isSuccessful;
    }

    public String getMessage() {
        return message;
    }

}
