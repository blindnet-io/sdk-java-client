package io.blindnet.blindnet;

import io.blindnet.blindnet.domain.UserRegistrationResult;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public interface UserService {

    UserRegistrationResult register();

    void unregister();

}
