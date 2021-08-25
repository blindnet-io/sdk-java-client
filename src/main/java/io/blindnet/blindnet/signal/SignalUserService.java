package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.UserRegistrationResult;
import org.whispersystems.libsignal.InvalidKeyException;

public interface SignalUserService {

    UserRegistrationResult register() throws InvalidKeyException;

    void unregister();

}
