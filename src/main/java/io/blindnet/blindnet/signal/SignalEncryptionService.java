package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.MessageArrayWrapper;
import io.blindnet.blindnet.domain.MessageStreamWrapper;

import java.util.List;

public interface SignalEncryptionService {

    // FR-SDK19
    void encryptMessage(List<String> recipientIds, MessageArrayWrapper messageArrayWrapper);

    // FR-SDK20
    List<MessageArrayWrapper> decryptMessage(String deviceId);

    void encryptMessage(List<String> recipientIds, MessageStreamWrapper messageStreamWrapper);

    List<MessageStreamWrapper> decryptStreamMessage(String deviceId);

}
