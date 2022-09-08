package io.blindnet.blindnet.internal;

import static java.util.Objects.requireNonNull;

/**
 * Provides singleton instance for Blindnet api server url.
 */
public enum ApiConfig {

    /**
     * Api Config Instance.
     */
    INSTANCE;

    /**
     * A Blindnet server url.
     */
    private String serverUrl = "https://blindnet-api-xtevwj4sdq-ew.a.run.app";

    /**
     * A constructor, which is private by default.
     */
    ApiConfig() {
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
