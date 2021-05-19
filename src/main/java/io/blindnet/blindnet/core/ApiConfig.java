package io.blindnet.blindnet.core;

import static java.util.Objects.requireNonNull;

/**
 * Provides singleton instance for blindnet api server url.
 */
public enum ApiConfig {

    /**
     * Api Config Instance.
     */
    INSTANCE;

    /**
     * A blindnet server url.
     */
    private String serverUrl = "https://blindnet-api-xtevwj4sdq-ew.a.run.app";

    /**
     * A constructor, which is private by default.
     */
    ApiConfig() {
    }

    /**
     * Returns Singleton Instance for Api Config.
     *
     * @return a Jwt Singleton.
     */
    public ApiConfig getInstance() {
        return INSTANCE;
    }

    /**
     * Sets a value of server url.
     *
     * @param serverUrl a server url.
     */
    public void setup(String serverUrl) {
        requireNonNull(serverUrl, "Server url cannot be null.");

        this.serverUrl = serverUrl;
    }

    /**
     * Returns server url.
     *
     * @return a server url.
     */
    public String getServerUrl() {
        return serverUrl;
    }

}
