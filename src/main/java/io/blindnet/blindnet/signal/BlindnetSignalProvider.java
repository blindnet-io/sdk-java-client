package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.BlindnetSignal;

public class BlindnetSignalProvider {

    private BlindnetSignalProvider() {
    }

    public static BlindnetSignal getInstance(String dbPath, String jwt) {
        return new BlindnetSignalImpl(dbPath, jwt);
    }

    public static BlindnetSignal getInstance(String dbPath, String jwt, String serverUrl) {
        return new BlindnetSignalImpl(dbPath, jwt, serverUrl);
    }

    public static BlindnetSignal getAndroidInstance(String jwt) {
        return new BlindnetSignalImpl(null, null, jwt);
    }

    public static BlindnetSignal getAndroidInstance(String jwt, String serverUrl) {
        return new BlindnetSignalImpl(null, jwt, serverUrl);
    }

}
