package io.blindnet.blindnet;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;

import java.io.InputStream;

/**
 * Provides api for core operations in blindnet sdk.
 */
public interface Blindnet {

    /**
     * Set jwt that will be used for authorsiation against blindnet api.
     *
     * @param jwt a jwt object.
     */
    void setJwt(String jwt);

    /**
     * Set url of a blindnet api.
     *
     * @param url a api url.
     */
    void setApiUrl(String url);

    /**
     * Encrypts private keys and sends them to blindnet api.
     *
     * @param password a password phrase used for encryption of private keys.
     */
    void encryptPrivateKeys(String password);

    /**
     * Fetches private keys from blindnet api and stores them locally.
     *
     * @param password a password phrase used for decryption of private keys.
     */
    void decryptPrivateKeys(String password);

    /**
     * Encrypts message.
     *
     * @param recipientId    a recipient id.
     * @param messageWrapper a message wrapper object.
     * @return encrypted message as byte array.
     */
    byte[] encrypt(String recipientId, MessageArrayWrapper messageWrapper);

    /**
     * Encrypts message.
     *
     * @param recipientId          a recipient id.
     * @param messageStreamWrapper a message wrapper object.
     * @return encrypted message as input stream.
     */
    InputStream encrypt(String recipientId, MessageStreamWrapper messageStreamWrapper);

    /**
     * Decrypts message.
     *
     * @param senderId    a sender id.
     * @param recipientId a recipient id.
     * @param data        encrypted message as byte array.
     * @return a message wrapper object.
     */
    MessageArrayWrapper decrypt(String senderId, String recipientId, byte[] data);

    /**
     * Decrypts message.
     *
     * @param senderId    a sender id.
     * @param recipientId a recipient id.
     * @param inputData   encrypted message as input stream.
     * @return a message wrapper object.
     */
    MessageStreamWrapper decrypt(String senderId, String recipientId, InputStream inputData);

    /**
     * Registers user on blindnet api.
     *
     * @return a user registration result object.
     */
    UserRegistrationResult register();

    /**
     * Unregisters user from blindnet api.
     */
    void unregister();

}
