package io.blindnet.blindnet.core;

import io.blindnet.blindnet.UserService;

public class UserServiceProvider {

    private UserServiceProvider() {}

    public static UserService getInstance() {
        return new UserServiceImpl();
    }

}
