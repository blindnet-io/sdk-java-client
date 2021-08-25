package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.MessageArrayWrapper;

import java.io.InputStream;
import java.util.List;

public interface SignalBackupService {

    void backup(String password, boolean newBackup, List<MessageArrayWrapper> messages);

    void backup(String password, boolean newBackup, InputStream messages);

    List<MessageArrayWrapper> recover(String password);

    InputStream recoverAsStream(String password);

}
