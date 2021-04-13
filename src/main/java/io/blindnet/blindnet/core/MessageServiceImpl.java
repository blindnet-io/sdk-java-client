package io.blindnet.blindnet.core;

import io.blindnet.blindnet.MessageService;

import java.security.GeneralSecurityException;

import static io.blindnet.blindnet.domain.EncryptionConstants.AES_ALGORITHM;
import static io.blindnet.blindnet.domain.EncryptionConstants.AES_KEY_SIZE_256;

public class MessageServiceImpl implements MessageService {

    //TODO: FR-SDK07; exposed
    @Override
    public void encrypt(String jwt, int recipientId, String data, String metadata) throws GeneralSecurityException {
        BlindnetClient blindnetClient = new BlindnetClient();
        // The sender id to be used here will be the id extracted from the JWT.
        blindnetClient.fetchSymmetricKey(jwt, 1, recipientId);

        // IF KEY NOT RETRIEVED
        //  retrieves the public key of the recipient, by sending a request to blindnet backend
        blindnetClient.fetchPublicKey(jwt, recipientId);

        // generates a random symmetric encryption key
        KeyFactory.generateSecretKey(AES_ALGORITHM, AES_KEY_SIZE_256);

        // encrypts the generated symmetric key two times and uploads both of them to blindnet
        // the sender id to be used here will be the id extracted from the JWT
        blindnetClient.sendSymmetricKeys(jwt, null,null);

        // combines message data and metadata, and encrypts everything with the symmetric key
        // todo; add encryption

    }

    //TODO: FR-SDK09; exposed
    @Override
    public void decrypt(String jwt, int senderId, int recipientId, String data) {
        BlindnetClient blindnetClient = new BlindnetClient();
        blindnetClient.fetchSymmetricKey(jwt, senderId, recipientId);

        // decrypts the encrypted data with the decrypted symmetric key
        // todo add decryption

        // splits the decrypted data into message data and message metadata
        // todo; add split logic and return response

    }

}
