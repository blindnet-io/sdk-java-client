package io.blindnet.blindnet.internal;

import static java.util.Objects.requireNonNull;

/**
 * Provides a Singleton instance for token configuration.
 */
public enum TokenConfig {

    /**
     * Token Config Instance.
     */
    INSTANCE;

    /**
     * A user's token.
     */
    private String token;

    /**
     * A constructor, which is private by default.
     */
    TokenConfig() {
    }

    /**
     * Sets a value of token object.
     *
     * @param token a token object as a string.
     */
    public void setup(String token) {
        requireNonNull(token, "Token cannot be null.");

        this.token = token;
    }

    /**
     * Returns token as a string.
     *
     * @return A token.
     */
    public String getToken() {
        return token;
    }

}
