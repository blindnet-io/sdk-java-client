package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.UserRegistrationResult;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * Provides API for user related operations.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
interface UserService {

    /**
     * Registers a user using Blindnet API.
     *
     * @return a user registration result object.
     */
    UserRegistrationResult register();

    /**
     * Unregisters a user using Blindnet API and deletes his local data.
     */
    void unregister();

}
