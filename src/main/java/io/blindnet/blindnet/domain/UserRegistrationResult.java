package io.blindnet.blindnet.domain;

import java.util.Objects;

/**
 * todo javadoc
 *
 * @author stefanveselinovic
 */
public class UserRegistrationResult {

    /**
     * Indicates whether the user registration is successful;
     */
    private final boolean isSuccessful;

    /**
     * Represents the
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
