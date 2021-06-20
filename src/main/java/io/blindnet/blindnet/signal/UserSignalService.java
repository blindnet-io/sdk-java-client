package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.UserRegistrationResult;

public interface UserSignalService {

    UserRegistrationResult register();

    void unregister();

}
