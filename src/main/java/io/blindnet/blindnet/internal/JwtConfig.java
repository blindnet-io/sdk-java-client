package io.blindnet.blindnet.internal;

import static java.util.Objects.requireNonNull;

/**
 * Provides Singleton instance for jwt configuration.
 */
public enum JwtConfig {

    /**
     * Jwt Config Instance.
     */
    INSTANCE;

    /**
     * A user's jwt.
     */
    private String jwt;

    /**
     * A constructor, which is private by default.
     */
    JwtConfig() {
    }

    /**
     * Sets a value of jwt object.
     *
     * @param jwt a jwt object as a string.
     */
    public void setup(String jwt) {
        requireNonNull(jwt, "JWT cannot be null.");

        this.jwt = jwt;
    }

    /**
     * Returns jwt as a string.
     *
     * @return A jwt.
     */
    public String getJwt() {
        return jwt;
    }

}
