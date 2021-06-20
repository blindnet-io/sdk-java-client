package io.blindnet.blindnet;

import io.blindnet.blindnet.domain.UserRegistrationResult;

public interface BlindnetSignal {

    UserRegistrationResult register();

    void unregister();

}
