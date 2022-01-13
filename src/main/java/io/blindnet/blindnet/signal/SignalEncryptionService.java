package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;

import java.util.List;

/**
 * Provides API for encryption and decryption of messages using Signal Blindnet API.
 */
interface SignalEncryptionService {

    /**
     * Encrypts message and sends to Signal Blindnet API.
     *
     * @param recipientIds the list of recipient ids.
     * @param messageArrayWrapper a message wrapper.
     */
    void encryptMessage(List<String> recipientIds, MessageArrayWrapper messageArrayWrapper);

    /**
     * Fetches messages from Signal Blindnet API and decrypts them.
     *
     * @param deviceId the id of the device.
     * @return a list of messages wrappers.
     */
    List<MessageArrayWrapper> decryptMessage(String deviceId);

    /**
     * Currently, Signal library does not support encryption/decryption of stream messages.
     */
    /*
     * void encryptMessage(List<String> recipientIds, MessageStreamWrapper messageStreamWrapper);
     */

    /**
     * Currently, Signal library does not support encryption/decryption of stream messages.
     */
    /*
     * List<MessageStreamWrapper> decryptStreamMessage(String deviceId);
     */

}
