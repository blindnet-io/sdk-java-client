package io.blindnet.blindnet;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.UserRegistrationResult;

import java.io.InputStream;
import java.util.List;

/**
 * Provides API for Signal operations in Blindnet SDK.
 */
public interface BlindnetSignal {

    /**
     * Registers user against Signal Blindnet API.
     *
     * @return user registration result object.
     */
    UserRegistrationResult register();

    /**
     * Unregisters user against Signal Blindnet API and deletes local user data.
     */
    void unregister();

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
     * Backups a list of messages using Signal Blindnet API.
     *
     * @param password a backup password.
     * @param newBackup flag indicating whether this is a new fresh backup.
     * @param messages a list of messages.
     */
    void backupMessages(String password, boolean newBackup, List<MessageArrayWrapper> messages);

    /**
     * Backups a stream of messages using Signal Blindnet API.
     *
     * @param password a backup password.
     * @param newBackup flag indicating whether this is a new fresh backup.
     * @param messages a stream of messages.
     */
    void backupMessages(String password, boolean newBackup, InputStream messages);

    /**
     * Recovers a list of messages from a backup.
     *
     * @param password a backup password.
     * @return a list of messages.
     */
    List<MessageArrayWrapper> recoverMessages(String password);

    /**
     * Recovers a stream of messages from a backup.
     *
     * @param password a backup password.
     * @return a stream of messages.
     */
    InputStream recoverMessagesAsStream(String password);

    // todo this will be removed
    int readDeviceId();

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
