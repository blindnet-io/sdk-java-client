package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.BlindnetSignal;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import io.blindnet.blindnet.internal.*;

public class BlindnetSignalImpl implements BlindnetSignal {

    private final UserSignalService userSignalService;
    private final JwtConfig jwtConfig = JwtConfig.INSTANCE;

    public BlindnetSignalImpl(String keyFolderPath, String jwt, String serverUrl) {
        this(keyFolderPath, jwt);
        ApiConfig.INSTANCE.setup(serverUrl);
    }

    public BlindnetSignalImpl(String keyFolderPath, String jwt) {
        KeyStorage keyStorage = KeyStorage.getInstance();
        if (keyFolderPath != null) {
            KeyStorageConfig.INSTANCE.setup(keyFolderPath);
        } else {
            keyStorage.isAndroid = true;
        }
        jwtConfig.setup(jwt);

        KeyFactory keyFactory = new KeyFactory();
        SigningService signingService = new SigningService();
        SignalApiClient signalApiClient = new SignalApiClient(HttpClient.getInstance(),
                keyFactory);

        userSignalService = new UserSignalServiceImpl(keyStorage,
                keyFactory,
                signingService,
                signalApiClient);
    }

    @Override
    public UserRegistrationResult register() {
        return userSignalService.register();
    }

    @Override
    public void unregister() {
        userSignalService.unregister();
    }

}
