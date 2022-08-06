package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.BlindnetSignal;

/**
 * Provides instance of default implementation of Signal Blindnet SDK API.
 */
public class BlindnetSignalProvider {

    private BlindnetSignalProvider() {
    }

    public static BlindnetSignal getInstance(String dbPath, String token) {
        return new BlindnetSignalImpl(dbPath, token);
    }

    public static BlindnetSignal getInstance(String dbPath, String token, String serverUrl) {
        return new BlindnetSignalImpl(dbPath, token, serverUrl);
    }

    public static BlindnetSignal getAndroidInstance(String token) {
        return new BlindnetSignalImpl(null, token, null);
    }

    public static BlindnetSignal getAndroidInstance(String token, String serverUrl) {
        return new BlindnetSignalImpl(null, token, serverUrl);
    }

}
