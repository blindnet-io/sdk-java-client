package io.blindnet.blindnet.core;

import io.blindnet.blindnet.UserService;

/**
 * Provides API for creation of User Service.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public final class UserServiceProvider {

    private UserServiceProvider() {
    }

    /**
     * Creates an instance of the User Service.
     *
     * @return a user service instance.
     */
    public static UserService getInstance() {
        KeyStorage keyStorage = KeyStorage.getInstance();
        KeyFactory keyFactory = new KeyFactory();

        BlindnetClient blindnetClient = new BlindnetClient(KeyStorage.getInstance(),
                keyFactory,
                new EncryptionService(keyFactory),
                HttpClient.getInstance(),
                new KeyEnvelopeService()
        );
        SigningService signingService = new SigningService();

        return new UserServiceImpl(keyStorage, keyFactory, signingService, blindnetClient);
    }

}
