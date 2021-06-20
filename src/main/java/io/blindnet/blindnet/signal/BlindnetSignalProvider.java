package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.BlindnetSignal;

public class BlindnetSignalProvider {

    private BlindnetSignalProvider() {
    }

    public static BlindnetSignal getInstance(String keyFolderPath, String jwt) {
        return new BlindnetSignalImpl(keyFolderPath, jwt);
    }

    public static BlindnetSignal getInstance(String keyFolderPath, String jwt, String serverUrl) {
        return new BlindnetSignalImpl(keyFolderPath, jwt, serverUrl);
    }

    public static BlindnetSignal getAndroidInstance(String jwt) {
        return new BlindnetSignalImpl(null, jwt);
    }

    public static BlindnetSignal getAndroidInstance(String jwt, String serverUrl) {
        return new BlindnetSignalImpl(null, jwt, serverUrl);
    }

}
