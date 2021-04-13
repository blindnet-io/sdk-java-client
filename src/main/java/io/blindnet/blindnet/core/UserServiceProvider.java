package io.blindnet.blindnet.core;

import io.blindnet.blindnet.UserService;

public class UserServiceProvider {

    private UserServiceProvider() {}

    public static UserService getInstance() {
        BlindnetClient blindnetClient = new BlindnetClient();
        KeyStorage keyStorage = new KeyStorage();
        JwtService signingService = new JwtService();

        return new UserServiceImpl(keyStorage, signingService, blindnetClient);
    }

}
