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

}
