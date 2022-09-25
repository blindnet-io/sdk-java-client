package io.blindnet.blindnet;

import io.blindnet.blindnet.domain.message.MessageArrayWrapper;
import io.blindnet.blindnet.domain.message.MessageStreamWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;

import java.io.InputStream;

/**
 * Provides API for core operations in Blindnet SDK.
 */
public interface Blindnet {

    /**
     * Update token that will be used for authorization against Blindnet api.
     *
     * @param token a token object.
     */
    void updateToken(String token);

    /**
     * Encrypts/backups private keys and sends them to Blindnet api.
     *
     * @param password a password phrase used for encryption of private keys.
     */
    void backupKeys(String password);

    /**
     * Retrieves private keys from Blindnet api and stores them locally.
     *
     * @param password a password phrase used for decryption of private keys.
     */
    void retrieveKeys(String password);

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
     * Registers user on Blindnet api.
     *
     * @return a user registration result object.
     */
    UserRegistrationResult register();

    /**
     * Unregisters/disconnects user from Blindnet api.
     */
    void disconnect();

}
