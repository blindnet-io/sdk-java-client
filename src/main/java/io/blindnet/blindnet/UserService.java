package io.blindnet.blindnet;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface UserService {

    String register(String jwt) throws GeneralSecurityException, IOException;

}
