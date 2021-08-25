package io.blindnet.blindnet.signal;

import io.blindnet.blindnet.domain.MessageArrayWrapper;

import java.util.List;

public interface SignalEncryptionService {

    // FR-SDK19
    void encryptMessage(List<String> recipientIds, MessageArrayWrapper messageArrayWrapper);

    // FR-SDK20
    List<MessageArrayWrapper> decryptMessage(String recipientId, String deviceId);

}
