package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.message.MessageArrayWrapper;

import java.io.InputStream;
import java.util.List;

/**
 * Provides API to back up and recover messages using Signal Blindnet API.
 */
interface SignalBackupService {

    /**
     * Backups list of messages using Signal Blindnet API.
     *
     * @param password a backup password.
     * @param newBackup flag indicating whether this is a new fresh backup.
     * @param messages a list of messages.
     */
    void backup(String password, boolean newBackup, List<MessageArrayWrapper> messages);

    /**
     * Backups a stream of messages using Signal Blindnet API.
     *
     * @param password a backup password.
     * @param newBackup flag indicating whether this is a new fresh backup.
     * @param messages a stream of messages.
     */
    void backup(String password, boolean newBackup, InputStream messages);

    /**
     * Recovers a list of messages from a backup.
     *
     * @param password a backup password.
     * @return a list of messages.
     */
    List<MessageArrayWrapper> recover(String password);

    /**
     * Recovers a stream of messages from a backup.
     *
     * @param password a backup password.
     * @return a stream of messages.
     */
    InputStream recoverAsStream(String password);

}
