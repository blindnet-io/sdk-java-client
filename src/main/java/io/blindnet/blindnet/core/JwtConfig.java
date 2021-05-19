package io.blindnet.blindnet.core;

import static java.util.Objects.requireNonNull;

/**
 * Provides Singleton instance for jwt configuration.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
enum JwtConfig {

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
     * Returns Singleton Instance for Jwt Config.
     *
     * @return a Jwt Singleton.
     */
    public JwtConfig getInstance() {
        return INSTANCE;
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
