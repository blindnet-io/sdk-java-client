package io.blindnet.blindnet.core;

import io.blindnet.blindnet.Blindnet;

/**
 * Provides instance of default implementation of Blindnet SDK api.
 */
public class BlindnetProvider {

    private BlindnetProvider() {}

    public static Blindnet getInstance(String keyFolderPath, String jwt) {
        return new BlindnetImpl(keyFolderPath, jwt);
    }

    public static Blindnet getInstance(String keyFolderPath, String jwt, String serverUrl) {
        return new BlindnetImpl(keyFolderPath, jwt, serverUrl);
    }

    public static Blindnet getAndroidInstance(String jwt) {
        return new BlindnetImpl(null, jwt);
    }

    public static Blindnet getAndroidInstance(String jwt, String serverUrl) {
        return new BlindnetImpl(null, jwt, serverUrl);
    }

}
