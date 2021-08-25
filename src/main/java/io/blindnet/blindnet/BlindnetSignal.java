package io.blindnet.blindnet;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;
import io.blindnet.blindnet.domain.SignalSendMessageResult;
import io.blindnet.blindnet.domain.UserRegistrationResult;
import org.whispersystems.libsignal.InvalidKeyException;

import java.io.InputStream;
import java.util.List;

public interface BlindnetSignal {

    UserRegistrationResult register() throws InvalidKeyException;

    void unregister();

    void encryptMessage(List<String> recipientIds, MessageArrayWrapper messageArrayWrapper);

    List<MessageArrayWrapper> decryptMessage(String recipientId, String deviceID);

    void backupMessages(String password, boolean newBackup, List<MessageArrayWrapper> messages);

    void backupMessages(String password, boolean newBackup, InputStream messages);

    List<MessageArrayWrapper> recoverMessages(String password);

    InputStream recoverMessagesAsStream(String password);

}
