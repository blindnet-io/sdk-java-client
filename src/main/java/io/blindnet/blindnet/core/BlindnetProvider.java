package io.blindnet.blindnet.core;

import io.blindnet.blindnet.Blindnet;

/**
 * Provides instance of default implementation of core Blindnet SDK API.
 */
public class BlindnetProvider {

    private BlindnetProvider() {}

    public static Blindnet getInstance(String keyFolderPath, String token) {
        return new BlindnetImpl(keyFolderPath, token);
    }

    public static Blindnet getInstance(String keyFolderPath, String token, String serverUrl) {
        return new BlindnetImpl(keyFolderPath, token, serverUrl);
    }

    public static Blindnet getAndroidInstance(String token) {
        return new BlindnetImpl(null, token);
    }

    public static Blindnet getAndroidInstance(String token, String serverUrl) {
        return new BlindnetImpl(null, token, serverUrl);
    }

}
