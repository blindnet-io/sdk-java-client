package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.message.MessageArrayWrapper;
import io.blindnet.blindnet.domain.message.MessageStreamWrapper;

import java.io.InputStream;

/**
 * Provides API for encryption and decryption of messages.
 */
interface MessageService {

    /**
     * Encrypts message and message metadata.
     *
     * @param recipientId an id of the recipient.
     * @param messageWrapper a message wrapper object.
     * @return encrypted message and message metadata as an byte array.
     */
    byte[] encrypt(String recipientId, MessageArrayWrapper messageWrapper);

    /**
     * Encrypts message and message metadata.
     *
     * @param recipientId an id of the recipient.
     * @param messageStreamWrapper a message wrapper object.
     * @return encrypted message and message metadata as an input stream.
     */
    InputStream encrypt(String recipientId, MessageStreamWrapper messageStreamWrapper);

    /**
     * Decrypts message and message metadata.
     *
     * @param senderId an id of the sender.
     * @param recipientId an id of the recipient.
     * @param data encrypted message and message metadata as byte array.
     * @return decrypted message and message metadata as message wrapper object.
     */
    MessageArrayWrapper decrypt(String senderId, String recipientId, byte[] data);

    /**
     * Decrypts message and message metadata.
     *
     * @param senderId an id of the sender.
     * @param recipientId an id of the recipient.
     * @param inputData encrypted message and message metadata as input stream.
     * @return decrypted message and message metadata as message wrapper object.
     */
    MessageStreamWrapper decrypt(String senderId, String recipientId, InputStream inputData);

}
