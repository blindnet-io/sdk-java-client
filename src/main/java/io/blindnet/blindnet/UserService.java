package io.blindnet.blindnet;

import io.blindnet.blindnet.domain.UserRegistrationResult;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface UserService {

    UserRegistrationResult register(String jwt);

}
