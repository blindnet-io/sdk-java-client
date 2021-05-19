package io.blindnet.blindnet.core;

import io.blindnet.blindnet.BlindnetSdkApi;

/**
 * Provides instance of default implementation of Blindnet SDK api.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class BlindnetSdkApiProvider {

    private BlindnetSdkApiProvider() {}

    public static BlindnetSdkApi getInstance() {
        return new BlindnetSdkApiImpl();
    }

}
