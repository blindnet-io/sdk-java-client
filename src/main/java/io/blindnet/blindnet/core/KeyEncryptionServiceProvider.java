package io.blindnet.blindnet.core;

import io.blindnet.blindnet.KeyEncryptionService;

public class KeyEncryptionServiceProvider {

    private KeyEncryptionServiceProvider() {}

    public static KeyEncryptionService getInstance() {
        return new KeyEncryptionServiceImpl();
    }

}
