package io.blindnet.blindnet.core;

import io.blindnet.blindnet.MessageService;

/**
 * Provides API for creation of Message Service.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public final class MessageServiceProvider {

    private MessageServiceProvider() {
    }

    /**
     * Creates an instance of the Message Service.
     *
     * @return a message service instance.
     */
    public static MessageService getInstance() {
        KeyFactory keyFactory = new KeyFactory();
        EncryptionService encryptionService = new EncryptionService(keyFactory);
        KeyEnvelopeService keyEnvelopeService = new KeyEnvelopeService();

        return new MessageServiceImpl(KeyStorage.getInstance(),
                keyFactory,
                encryptionService,
                new SigningService(),
                keyEnvelopeService,
                new BlindnetClient(KeyStorage.getInstance(),
                        keyFactory,
                        encryptionService,
                        HttpClient.getInstance(),
                        keyEnvelopeService
                ));
    }

}
