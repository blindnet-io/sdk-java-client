package io.blindnet.blindnet.core;

import io.blindnet.blindnet.KeyEncryptionService;

/**
 * Provides API for creation of Key Encryption Service.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class KeyEncryptionServiceProvider {

    private KeyEncryptionServiceProvider() {
    }

    /**
     * Creates an instance of the Key Encryption Service.
     *
     * @return a key encryption service instance.
     */
    public static KeyEncryptionService getInstance() {
        KeyFactory keyFactory = new KeyFactory();
        EncryptionService encryptionService = new EncryptionService(keyFactory);

        return new KeyEncryptionServiceImpl(KeyStorage.getInstance(),
                keyFactory,
                encryptionService,
                new BlindnetClient(KeyStorage.getInstance(),
                        keyFactory,
                        encryptionService,
                        HttpClient.getInstance(),
                        new KeyEnvelopeService()));
    }

}
