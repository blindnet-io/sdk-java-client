package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.UserRegistrationResult;
import org.whispersystems.libsignal.InvalidKeyException;

/**
 * Provides API to register/unregister user against Signal Blindnet API.
 */
interface SignalUserService {

    /**
     * Registers user against Signal Blindnet API.
     *
     * @return user registration result object.
     */
    UserRegistrationResult register();

    /**
     * Unregisters user against Signal Blindnet API and deletes local user data.
     */
    void unregister();

}
